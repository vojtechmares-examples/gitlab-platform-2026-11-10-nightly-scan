#!/usr/bin/env bash
# shellcheck disable=SC2029  # the variable is meant to expand on this side, into the remote command
# Print the images that run in one environment of the deploy server, one per line. The container units read the image from
# /var/lib/examples/<app>/<env>/image.env (written by the deploy pipelines), so that file is the source of truth.
#   scripts/deployed-images.sh staging|production
set -euo pipefail

ENVIRONMENT="${1:?usage: deployed-images.sh staging|production}"
ssh deploy "cat /var/lib/examples/*/${ENVIRONMENT}/image.env 2>/dev/null" | sed -n 's/^IMAGE=//p' | sort -u
