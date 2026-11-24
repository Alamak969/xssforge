# Security Policy

## Supported versions
Only the latest public release of xssforge receives fixes.

## Reporting a vulnerability
Please do **not** open a public issue for security problems in this tool.

Use GitHub's private **Security → Report a vulnerability** form on this
repository, or contact the maintainer privately. Include:
- affected version / commit
- reproduction steps
- impact (for example: unintended network access, unsafe default, secret leak)
- suggested fix, if you have one

You should receive an acknowledgement within 7 days. Please allow time for a
fix before public disclosure.

## Scope
Reports about the scanner's own safety are in scope: accidental scanning of
out-of-scope hosts, credential leakage into reports, unsafe deserialization,
command injection through input files, and similar defects.

Reports about vulnerabilities found *using* xssforge on third-party sites
should go to the affected vendor's security program, not here.
