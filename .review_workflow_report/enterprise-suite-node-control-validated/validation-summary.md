# Enterprise Workflow Scanner Validation

Overall: **PASS**

| Case | Gate | Findings | Risk chains | Result |
|---|---:|---:|---:|---:|
| safe-workflow | PASS | 0 | 0 | PASS |
| approval-protected-workflow | PASS | 0 | 0 | PASS |
| approval-bypass-workflow | FAIL | 1 | 1 | PASS |
| keyword-spoofed-control | FAIL | 1 | 3 | PASS |
| parameter-precision-workflow | PASS | 0 | 0 | PASS |
| text-optimization-workflow | REVIEW | 2 | 1 | PASS |
| review-only-workflow | REVIEW | 1 | 0 | PASS |
| non-strict-schema-workflow | FAIL | 2 | 3 | PASS |
| document-indirect-injection-workflow | FAIL | 5 | 5 | PASS |
| risky-workflow | FAIL | 15 | 13 | PASS |
| tencent-inspired-workflow | FAIL | 33 | 34 | PASS |
