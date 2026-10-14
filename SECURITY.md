# Security policy

## Supported versions

Before the first release, fixes target the current `main` branch. There is no stable release
or support commitment for older CI artifacts.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/ArcForges/ArcForges/security/advisories/new)
when available. Include the affected commit, operating system, reproduction steps and impact.
If private reporting is unavailable, open a public issue requesting a private contact
without disclosing the vulnerability. Never put credentials or exploit details in public issues.

## Current boundary

- `arcforges` has no roles yet: it opens no endpoint, runs no command and stores nothing.
- `arcforges-desktop` shows an offline bootstrap view: it requests no elevation, executes no
  external commands and stores no credentials.
- The development tools are not shipped. `arcforges-testload` deliberately consumes CPU and
  memory, writes output and starts copies of itself, within the bounds its parameters allow;
  `arcforges-bench` starts the executable it is given. Run them only with commands you trust.

Tests of this foundation do not prove the security of the future node, scheduling, LAN,
authentication or cloud functionality; those tasks bring their own threat-specific tests.

CI uses locked NuGet dependencies with recorded admissions (`eng/policy/dependency-admissions.json`),
vulnerability auditing, dependency review, CodeQL, gitleaks secret scanning and immutable action
references. PR jobs do not receive deployment credentials or publish releases. These checks
complement review; they are not a security guarantee.

GitHub private reporting, push protection and required-check rules are repository settings,
not enabled by this file. Maintainers configure them separately. No response SLA is promised.
