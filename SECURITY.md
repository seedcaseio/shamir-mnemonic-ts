# Security Policy

## Supported versions

Only the latest release line receives security fixes.

| Version | Supported |
|---|---|
| 1.3.x | Yes |
| < 1.3 | No |

## Reporting a vulnerability

Please report suspected vulnerabilities privately by email to contact@seedcase.io. Do not open a public issue or pull request for a security problem.

Include, if possible:

- the affected version;
- a description of the problem and its impact;
- steps or code to reproduce it.

Never send real seed phrases, shares or passphrases: use the test vectors in `tests/vectors.json` or freshly generated test secrets.

## Known limitations

These are documented in the README and are not considered vulnerabilities:

- Wiping secret buffers is best effort: JavaScript can keep copies in memory, and strings cannot be wiped.
- Hiding secret bytes from logs is a safety net against accidental logging, not a protection against code that reads the objects.
- As specified by SLIP-0039, a wrong passphrase silently recovers a different secret.

Thank you for helping keep Seedcase and its users safe.
