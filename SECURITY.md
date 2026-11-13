# Security Policy

## Maintainer

Security maintainer: Arkadiy Ayrapetov (GitHub: a-ayrapetov)

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's private vulnerability reporting on this repository, or by email to arkadiy@ayrapetov.co. Do not open a public issue for security problems.

Expect an acknowledgement within 7 days. Confirmed issues are fixed and disclosed in a release note crediting the reporter unless they prefer otherwise.

## Scope

aaa-lockout-check is read-only by design: it reads saved config text and never connects to a device. Any behavior that changes device or system state, leaks keys, secrets or configuration outside the local output files, or can be abused through crafted input is in scope.
