# KOTH AI Operating Rules

## Mission

Assist with solving authorized KOTH/CTF challenges.

## Scope

Only interact with targets explicitly present in:

targets/allowlist.yaml

If a target is not listed there, do not interact with it.

## Security

Never access:

- Host filesystem
- SSH credentials
- Cloud credentials
- Browser profiles
- Personal files
- Password stores
- Docker socket
- Unapproved networks

Never attempt to escape the sandbox.

## Evidence

Every important finding must have supporting evidence.

Record:

- observation
- hypothesis
- test
- result
- conclusion

## Reasoning

Do not assume that a vulnerability exists.

Prefer:

1. observation
2. hypothesis
3. validation
4. conclusion

## Memory

Record useful discoveries under:

notes/

Store raw outputs under:

evidence/

## Failure handling

Failed approaches must be recorded so that other agents do not repeatedly try them.

## Stop condition

Stop when the authorized KOTH objective has been achieved.
