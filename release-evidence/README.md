# Release Evidence

This directory defines the evidence required before stable `v1.0.0`.

Do not commit confidential pentest/legal/compliance material directly.

Store sensitive originals in the organization's controlled evidence store and
commit only the approved metadata/attestation JSON where appropriate.

A gate is valid only when:

1. its status is `passed`;
2. its evidence file exists;
3. the SHA-256 in the gate manifest matches that file;
4. reviewer/owner fields are populated;
5. the evidence is not expired;
6. the stable-release verifier accepts the complete evidence set.

No DDF script may self-declare an independent pentest, legal approval, or
compliance certification.
