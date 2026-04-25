# Security Policy

## Supported Versions

`cyntrisec-cli` is a historical pre-company project, not a current Cyntrisec product or support surface.

Before archive, critical security reports affecting the final historical package may be reviewed. New features and non-critical maintenance are out of scope.

## Reporting a Vulnerability

Please report security issues privately.

- Preferred: open a GitHub Security Advisory for this repository.
- Avoid public issues or discussions for sensitive reports.
- Include clear reproduction steps, impact, affected versions, and any safe proof of concept.
- Do not include secrets, access keys, or sensitive customer data in reports.

If the report affects the final historical package and is exploitable in realistic use, we will coordinate a fix or publish a clear advisory. Otherwise, the repository should be treated as archived historical software.

## Scope

In scope:
- Critical vulnerabilities in the final historical `cyntrisec` package.
- Issues that could expose local scan data, AWS credentials, or generated artifacts.

Out of scope:
- Third-party dependencies (please report those to the upstream project).
- Social engineering or physical attacks.
