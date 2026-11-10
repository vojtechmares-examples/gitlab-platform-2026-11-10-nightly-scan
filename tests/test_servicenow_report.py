import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))

import servicenow_report as report  # noqa: E402

SAMPLE = json.loads((HERE / "sample-trivy.json").read_text())


class ScoreTests(unittest.TestCase):
    def test_the_highest_v3_score_of_any_source_wins(self):
        self.assertEqual(report.best_score({"nvd": {"V3Score": 9.8}, "redhat": {"V3Score": 9.1}}), 9.8)

    def test_v2_is_used_only_when_there_is_no_v3(self):
        self.assertEqual(report.best_score({"nvd": {"V2Score": 10.0}}), 10.0)
        self.assertEqual(report.best_score({"nvd": {"V2Score": 10.0, "V3Score": 5.0}}), 5.0)

    def test_missing_cvss_scores_zero(self):
        self.assertEqual(report.best_score(None), 0.0)
        self.assertEqual(report.best_score({}), 0.0)


class FilterTests(unittest.TestCase):
    def test_the_threshold_is_inclusive_and_lower_scores_are_dropped(self):
        found = {f.cve for f in report.findings_at_or_above(SAMPLE, 9.0)}

        self.assertEqual(found, {"CVE-2021-42013", "CVE-2099-0001", "CVE-2099-0002"})

    def test_findings_are_sorted_by_score_descending(self):
        scores = [f.score for f in report.findings_at_or_above(SAMPLE, 9.0)]

        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_a_clean_report_has_no_findings(self):
        self.assertEqual(report.findings_at_or_above({"ArtifactName": "x", "Results": []}, 9.0), [])
        self.assertEqual(report.findings_at_or_above({"ArtifactName": "x"}, 9.0), [])


class TaskTests(unittest.TestCase):
    def test_the_correlation_id_is_stable_and_depends_on_the_cves(self):
        findings = report.findings_at_or_above(SAMPLE, 9.0)

        first = report.build_task("httpd:2.4.50", findings, "https://example/pipelines/1")
        again = report.build_task("httpd:2.4.50", findings, "https://example/pipelines/2")
        other = report.build_task("httpd:2.4.50", findings[:1], "https://example/pipelines/1")

        self.assertEqual(first["correlation_id"], again["correlation_id"])
        self.assertNotEqual(first["correlation_id"], other["correlation_id"])

    def test_priority_one_for_9_8_and_above(self):
        findings = report.findings_at_or_above(SAMPLE, 9.0)

        self.assertEqual(report.build_task("t", findings, "u")["priority"], "1")
        self.assertEqual(report.build_task("t", [f for f in findings if f.score < 9.8], "u")["priority"], "2")


class EndToEndTests(unittest.TestCase):
    def test_without_servicenow_url_it_is_a_dry_run_that_writes_the_tasks(self):
        os.environ.pop("SERVICENOW_URL", None)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "tasks.json"
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = report.main([str(HERE / "sample-trivy.json"), "--output", str(output)])

            tasks = json.loads(output.read_text())

        self.assertEqual(code, 0)
        self.assertIn("DRY RUN", buffer.getvalue())
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["target"], "httpd:2.4.50")
        self.assertEqual(tasks[0]["number"], "dry-run")

    def test_a_clean_image_creates_no_task(self):
        os.environ.pop("SERVICENOW_URL", None)
        with tempfile.TemporaryDirectory() as tmp:
            clean = Path(tmp) / "clean.json"
            clean.write_text(json.dumps({"ArtifactName": "clean:1", "Results": []}))
            output = Path(tmp) / "tasks.json"
            with contextlib.redirect_stdout(io.StringIO()):
                report.main([str(clean), "--output", str(output)])

            self.assertEqual(json.loads(output.read_text()), [])


if __name__ == "__main__":
    unittest.main()
