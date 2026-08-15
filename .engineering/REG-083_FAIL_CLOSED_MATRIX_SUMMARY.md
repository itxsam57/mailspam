# REG-083 — Fail-Closed Matrix Summary

Status: **LOCKED**

## Defect

The Engineering Gate summary job could finish successfully after printing platform artifacts even when one Windows/macOS/Ubuntu matrix job had failed. That made the summary status misleading even though the failed platform job itself remained visible.

## Root repair

The summary job now consumes `needs.verify.result` and exits non-zero unless the complete platform matrix result is `success`. It still downloads and prints diagnostic artifacts first, so failures remain inspectable while the overall workflow is unambiguously red.

## Permanent protection

`tests/unit/engineeringAutomation.test.ts` requires the workflow to bind `VERIFY_RESULT` to `${{ needs.verify.result }}` and enforce a non-success exit.

No release or merge may use a summary that is green while any required platform gate is non-successful.