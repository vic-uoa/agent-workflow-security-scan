# Enterprise Workflow Scanner Validation

Overall: **PASS**

| Case | Gate | Findings | Risk chains | Result |
|---|---:|---:|---:|---:|
| safe-workflow | PASS | 0 | 0 | PASS |
| approval-protected-workflow | PASS | 0 | 0 | PASS |
| approval-bypass-workflow | FAIL | 1 | 1 | PASS |
| keyword-spoofed-control | FAIL | 5 | 3 | PASS |
| parameter-precision-workflow | PASS | 0 | 0 | PASS |
| review-only-workflow | REVIEW | 2 | 0 | PASS |
| non-strict-schema-workflow | FAIL | 8 | 2 | PASS |
| document-indirect-injection-workflow | FAIL | 17 | 5 | PASS |
| risky-workflow | FAIL | 45 | 14 | PASS |
| tencent-inspired-workflow | FAIL | 103 | 34 | PASS |
