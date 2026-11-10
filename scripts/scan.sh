#!/bin/sh
# Scan every image listed in the given files with Trivy and write one JSON report per image to reports/.
# Runs in the Trivy image (Alpine: /bin/sh only).   [REPORT_DIR=reports] scripts/scan.sh targets-staging.txt [more files ...]
set -eu

REPORT_DIR="${REPORT_DIR:-reports}"
mkdir -p "${REPORT_DIR}"
cat "$@" | grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' | sort -u | while read -r image; do
  out="${REPORT_DIR}/$(printf '%s' "${image}" | tr '/:' '__').json"
  echo "==> scanning ${image}"
  # --exit-code 0: finding vulnerabilities is the normal case here; the report script decides what to do about them
  trivy image --scanners vuln --severity HIGH,CRITICAL --exit-code 0 --format json --output "${out}" "${image}"
  echo "    $(wc -c < "${out}") bytes -> ${out}"
done
ls "${REPORT_DIR}"
