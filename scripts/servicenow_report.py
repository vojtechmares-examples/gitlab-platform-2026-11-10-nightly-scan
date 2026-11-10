#!/usr/bin/env python3
"""Read Trivy JSON reports, pick the vulnerabilities with a CVSS score of at least 9.0 and create one ServiceNow task per
scanned target (or print what would be created).

    servicenow_report.py REPORT.json [REPORT.json ...] [--threshold 9.0] [--output servicenow-tasks.json]

Without SERVICENOW_URL nothing is sent: the tasks are only printed and written to the output file ("dry run"). With it, each
task is POSTed to the ServiceNow Table API (SERVICENOW_USER / SERVICENOW_PASSWORD, table SERVICENOW_TABLE, default "task").
The correlation id is stable (target + the set of CVEs), so a later run can find the task it already opened.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    cve: str
    package: str
    installed: str
    fixed: str
    score: float
    severity: str
    title: str


def best_score(cvss: dict | None) -> float:
    """The highest CVSS v3 score any source (NVD, Red Hat, GitHub ...) gives; v2 only when there is no v3."""
    best_v3 = best_v2 = 0.0
    for source in (cvss or {}).values():
        best_v3 = max(best_v3, float(source.get("V3Score") or 0))
        best_v2 = max(best_v2, float(source.get("V2Score") or 0))
    return best_v3 or best_v2


def findings_at_or_above(report: dict, threshold: float) -> list[Finding]:
    found: dict[tuple[str, str], Finding] = {}
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            score = best_score(vuln.get("CVSS"))
            if score < threshold:
                continue
            finding = Finding(
                cve=vuln["VulnerabilityID"],
                package=vuln.get("PkgName", "?"),
                installed=vuln.get("InstalledVersion", "?"),
                fixed=vuln.get("FixedVersion") or "no fix yet",
                score=score,
                severity=vuln.get("Severity", "?"),
                title=vuln.get("Title") or "",
            )
            found[(finding.cve, finding.package)] = finding
    return sorted(found.values(), key=lambda f: (-f.score, f.cve, f.package))


def build_task(target: str, findings: list[Finding], pipeline_url: str) -> dict:
    cves = sorted({f.cve for f in findings})
    correlation = hashlib.sha256(f"{target}|{','.join(cves)}".encode()).hexdigest()[:32]
    lines = [f"{f.cve}  CVSS {f.score:.1f}  {f.package} {f.installed} (fix: {f.fixed})" for f in findings[:25]]
    if len(findings) > 25:
        lines.append(f"... and {len(findings) - 25} more")
    return {
        "short_description": f"{len(cves)} critical vulnerabilities (CVSS >= 9.0) in {target}",
        "description": "Found by the nightly Trivy scan.\n\n" + "\n".join(lines) + f"\n\nPipeline: {pipeline_url}",
        "category": "Security",
        "priority": "1" if any(f.score >= 9.8 for f in findings) else "2",
        "correlation_id": correlation,
    }


class ServiceNow:
    """A minimal Table API client. Dry run unless SERVICENOW_URL is set."""

    def __init__(self) -> None:
        self.url = os.environ.get("SERVICENOW_URL", "").rstrip("/")
        self.table = os.environ.get("SERVICENOW_TABLE", "task")
        self.user = os.environ.get("SERVICENOW_USER", "")
        self.password = os.environ.get("SERVICENOW_PASSWORD", "")

    @property
    def dry_run(self) -> bool:
        return not self.url

    def create(self, task: dict) -> str:
        if self.dry_run:
            return "dry-run"
        request = urllib.request.Request(
            f"{self.url}/api/now/table/{self.table}",
            data=json.dumps(task).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "Basic " + base64.b64encode(f"{self.user}:{self.password}".encode()).decode(),
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - the URL is configuration
            return json.load(response)["result"]["number"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("reports", nargs="+", help="Trivy JSON reports (trivy image --format json)")
    parser.add_argument("--threshold", type=float, default=9.0, help="lowest CVSS score that opens a task (default 9.0)")
    parser.add_argument("--output", default="servicenow-tasks.json", help="where to write the tasks that were created")
    args = parser.parse_args(argv)

    pipeline_url = os.environ.get("CI_PIPELINE_URL", "(local run)")
    client = ServiceNow()
    created = []
    print(f"ServiceNow: {'DRY RUN, nothing is sent (SERVICENOW_URL is not set)' if client.dry_run else client.url}")
    print(f"Threshold: CVSS >= {args.threshold}\n")

    for path in args.reports:
        with open(path, encoding="utf-8") as handle:
            report = json.load(handle)
        target = report.get("ArtifactName", path)
        findings = findings_at_or_above(report, args.threshold)
        if not findings:
            print(f"OK     {target}: nothing at or above {args.threshold}")
            continue
        task = build_task(target, findings, pipeline_url)
        number = client.create(task)
        created.append({"target": target, "number": number, **task})
        print(f"TASK   {target}: {len(findings)} finding(s), top score {findings[0].score:.1f} -> {number}")
        for finding in findings[:5]:
            print(f"         {finding.cve}  {finding.score:.1f}  {finding.package} {finding.installed}")

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(created, handle, indent=2)
    print(f"\n{len(created)} task(s) written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
