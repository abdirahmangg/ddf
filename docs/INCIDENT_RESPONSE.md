# Incident Response Runbook

## Security events

Treat the following as security events:

- compromised sponsor or agent signing key
- unexpected authority-chain validation failure
- replay-detection surge
- unexplained capability consumption
- evidence-chain integrity failure
- OpenFGA policy drift
- tenant-isolation or IDOR report

## Immediate actions

1. Revoke affected identity/key.
2. Revoke affected authority roots with cascade where appropriate.
3. Preserve evidence and request logs.
4. Rotate service/system signing material when affected.
5. Disable compromised integration credentials.
6. Validate OpenFGA tuples/model state.
7. Identify every descendant authority and issued capability.
8. Record timeline, owner and remediation.
9. Perform post-incident verification before restoring issuance.

Named organizational owners and escalation contacts are an external release gate.
