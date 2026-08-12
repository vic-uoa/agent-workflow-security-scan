# Enterprise Workflow Scanner Validation

Overall: **PASS**

| Case | Gate | Findings | Risk chains | Result |
|---|---:|---:|---:|---:|
| safe-workflow | PASS | 0 | 0 | PASS |
| approval-protected-workflow | PASS | 0 | 0 | PASS |
| approval-bypass-workflow | FAIL | 1 | 1 | PASS |
| keyword-spoofed-control | FAIL | 4 | 3 | PASS |
| parameter-precision-workflow | PASS | 0 | 0 | PASS |
| text-optimization-workflow | REVIEW | 2 | 1 | PASS |
| review-only-workflow | REVIEW | 1 | 0 | PASS |
| non-strict-schema-workflow | FAIL | 5 | 2 | PASS |
| document-indirect-injection-workflow | FAIL | 11 | 5 | PASS |
| risky-workflow | FAIL | 32 | 14 | PASS |
| tencent-inspired-workflow | FAIL | 74 | 34 | PASS |
