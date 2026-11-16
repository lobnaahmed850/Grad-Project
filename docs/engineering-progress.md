# Integration mission

Branch: `engineering/integrated-netguard`, based on `origin/AI` at `0c4d86c`.
The existing `ml-pipeline-fix` worktree and original serialized models are preserved.
Its uncommitted source, tests, lab, and historical reports were copied into this
branch before changes. Historical reports are evidence of previous experiments,
not release acceptance results.

## Baseline gaps

1. `main` only runs the syslog collector. AI and local fixes are separate.
2. The default loader selects public-data candidates, not the best lab recipe.
3. Attack evaluation divides one capture into random halves.
4. Source rate uses future capture information.
5. Extraction is offline, with no bounded live flow lifecycle.
6. No common persistent ingestion or dashboard exists.
7. Syslog timestamp, process attribution, and Windows-format defects persist.
8. The old lab grants router SYS_ADMIN and lacks service resource limits.
9. The 31 ms historical benchmark is not a live end-to-end measurement.
10. Dataset and model provenance are not enforced at the release boundary.

## Execution phases

- [x] Inspect branches, worktrees, artifacts, prior tools and Docker availability.
- [x] Establish baseline tests and model benchmark.
- [x] Implement causal features and shared offline/live flow lifecycle.
- [x] Build independent-session capture/training/calibration/evaluation.
- [x] Export and validate a versioned default bundle.
- [x] Repair syslog parsing and implement shared alert storage/API/dashboard.
- [x] Run isolated Docker traffic through live inference and both alert inputs.
- [x] Test reliability and measure latency, throughput and resource use.
- [x] Update instructions, notebook workflows and final technical evidence.

## Scope

Laboratory completion is distinct from production readiness. No synthetic result
establishes external-network generalization. No original model or capture will be
overwritten. Remote publishing and merging are outside this mission.

## Observed evidence

Baseline: 43 passed, one optional-model skip. Expanded suite and measured evidence
are recorded in the technical report and JUnit output. Both releases use
role-disjoint captures, training-fitted preprocessing and frozen calibration
selection. The first release's 27 captures yielded 1.90% held-out FPR, but a
fresh concurrent workload exposed 6.0% FPR. The second release adds independent
mixed workloads and longer normal runs: 36 captures, 0.41% final novel-flow FPR
(descriptive Wilson 0.16–1.04%). This remains synthetic same-host evidence.

The live demo passed fresh benign/scan/flood/slow scenarios, shared syslog/ML
storage, ingestion-outage durable replay and actual postrestart sensor verdicts.
The capture ring eliminated the earlier kernel-buffer loss under this bounded
workload. Late timestamp drops remain counted; this is not a lossless capture
claim. RF-only is the measured selected recipe, replacing the historical chosen
candidate default while retaining explicit legacy loading.
