# Security policy

## Supported versions

During bootstrap, fixes target the current `main` branch. There is no stable release
or support commitment for older CI artifacts.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/ArcForges/ArcForges/security/advisories/new)
when available. Include the affected commit, operating system, reproduction steps and impact.
If private reporting is unavailable, open a public issue requesting a private contact
without disclosing the vulnerability. Never put credentials or exploit details in public issues.

## Current boundary

The Hello World application operates offline, requests no elevation, executes no external
commands and stores no credentials. Tests do not prove the security of future resource-control,
agent, authentication or cloud functionality.

CI uses locked NuGet dependencies, vulnerability auditing, dependency review, CodeQL,
secret scanning and immutable action references. PR jobs do not receive deployment credentials
or publish releases. These checks complement review; they are not a security guarantee.

GitHub private reporting, push protection and required-check rules are repository settings,
not enabled by this file. Maintainers should configure them separately. No response SLA is promised.
