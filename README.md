# nightly-scan

A **scheduled pipeline** that scans container images with Trivy every night at midnight and opens **ServiceNow tasks** for
vulnerabilities with a CVSS score of **9.0 or higher**.

| Step | What happens |
|------|--------------|
| Schedule | *Build > Pipeline schedules*: `0 0 * * *`, time zone Prague, branch `main`. *Play* runs it now; *Run pipeline* starts the same jobs by hand |
| `discover` | per environment (`staging`, `production`): the images that run on the deploy server (read from `/var/lib/examples/*/<env>/image.env`) plus the base images in `targets/base-images.txt`. Production also scans `targets/production-canary.txt`: an old Apache with critical CVEs that keeps the ServiceNow path exercised |
| `scan` | Trivy (through the Dependency Proxy) scans each image; one JSON report per image. The deployed images come from the project registries, read with a group deploy token (`SCAN_REGISTRY_USER` / `SCAN_REGISTRY_TOKEN`) |
| `report` | `scripts/servicenow_report.py` reads the reports, takes the highest CVSS v3 score any source gives (v2 when there is no v3), and creates **one task per image** that has findings at or above the threshold. The task carries a stable `correlation_id` (image + CVE set) so a later run can recognise it |
| ServiceNow | a **dry run** until `SERVICENOW_URL` is set: the tasks are printed and kept as the artifact `servicenow-tasks-<env>.json`. Set `SERVICENOW_URL`, `SERVICENOW_USER`, `SERVICENOW_PASSWORD` (and optionally `SERVICENOW_TABLE`, default `task`) as CI/CD variables scoped to the `production` environment to send them to the Table API |
| Environments | `staging` is informational, `production` is where tasks are opened |

The report script has unit tests (`tests/`, run on every push) that cover the 9.0 threshold, the v2 fallback and the task payload.

## CI configuration

The scheduled jobs read the CI/CD variables below (*Settings > CI/CD > Variables*). Variables that start with `CI_` are predefined by GitLab.

| Variable | Set on | Type | Used for |
|----------|--------|------|----------|
| `DEPLOY_HOST` | group `examples` | Variable | Address of the deploy server; `discover` reads the deployed images from it |
| `DEPLOY_SSH_PORT` | group `examples` | Variable | SSH port of the deploy server (`6022`) |
| `DEPLOY_USER` | group `examples` | Variable | Account the pipelines log in as (`deploy`) |
| `SSH_KNOWN_HOSTS` | group `examples` | Variable | Host keys of the deploy server; the connection uses `StrictHostKeyChecking yes` |
| `SSH_PRIVATE_KEY` | group `examples` | File, **protected** | Private key of the `deploy` account |
| `SCAN_REGISTRY_USER` | this project | Variable | User name of a group deploy token of `examples` (scope `read_registry`) |
| `SCAN_REGISTRY_TOKEN` | this project | Variable, **masked** | The token itself. `scan` passes both to Trivy (`TRIVY_USERNAME`, `TRIVY_PASSWORD`) to pull the deployed images from the project registries |
| `SERVICENOW_URL` | optional, this project, scope `production` | Variable | Base URL of the ServiceNow instance. Without it `report` is a dry run |
| `SERVICENOW_USER`, `SERVICENOW_PASSWORD` | optional, this project, scope `production` | Variable (mask the password) | Credentials for the Table API |
| `SERVICENOW_TABLE` | optional, this project, scope `production` | Variable | Table that receives the tasks (default `task`) |

The group variables are inherited by every project in the `examples` group, so nothing has to be set for them here. The `.ssh-setup` snippet of `examples/ci-templates` turns the first five into `ssh deploy`.
The schedule runs on `main`, which is protected, so the protected `SSH_PRIVATE_KEY` reaches it. The `report` job runs in the environment `production` (and `staging`), which is what makes the variables scoped to `production` visible to it.
