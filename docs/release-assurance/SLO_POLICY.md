# Stable Release SLO Evidence

Stable release requires observed evidence from a representative deployment.

Record at minimum:

- observation start/end
- request count
- availability
- error rate
- p50 / p95 / p99 latency
- saturation/resource observations
- dependency failure observations
- readiness/liveness behavior
- incident count during the observation window

Suggested pre-v1.0 release target:

- availability >= 99.9% during the observation window
- server-side 5xx rate < 0.1%
- no unresolved Critical/High security incidents
- no integrity failures in authority/evidence processing

These are release targets, not contractual SLAs.
