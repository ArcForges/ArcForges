# Per-application secrets (PLT.40)

This nonpackable first-party building block stores opaque `SecretRef` values in the
owning app installation's credential namespace. The namespace includes realm,
account, product, device, installation, partition and secret identity. Composition
maps its trusted `AppIdentity` into the closed local `SecretApplicationDimension`
storage dimension (not a second product-identity authority); arbitrary product strings
are rejected, and the secrets package does not depend on the application-composition layer.
A reference has no readable identifier or plaintext representation; session sign-out
revokes use (`RevokeAllConnectorGrants`) without deleting the local vault.

The broker exposes store/delete and a short-lived connector-use grant, not a
secret-returning method. A grant is issued by the foreground direct-human host,
bound to the full planned actor chain and connector definition, and revalidated
against the live signed-in foreground session and recovery generation at use.
Credential-bearing work runs in the trusted app host executor; connector IPC must
never carry the secret bytes.

## What the isolation does and does not prove

Two different things are called isolation, and this package keeps them apart.

- **Broker namespace (proved offline).** Cross-product, cross-realm, cross-account,
  cross-device and cross-installation references, a delegated agent or extension acting as
  the human owner, a revoked or expired grant, a changed recovery generation and an ended
  foreground session all fail inside the owning host. Own sign-out leaves other
  applications' vaults and local data intact. This constrains only code that goes through
  the owning host's broker.
- **OS-enforced sibling denial (store property, declared not assumed).** Each
  `ISecretBackingStore` declares a `SecretStoreIsolation`. A broker is constructed with an
  explicit `SecretIsolationPolicy`: `RequireOsEnforcedPerApplication` fails closed unless the
  store declares `OsEnforcedPerApplication`; `AllowSameUserSharedStore` records that the host
  accepts the weaker assurance. `SecretBroker.IsolationAssurance` reports the declared class
  so release gates can refuse to claim more.

`WindowsCredentialManagerSecretStore` is the current-user Windows adapter and declares
`SameUserShared`. Credential Manager is addressable by name from every process of the same
Windows user, so it is **not** an OS-enforced sibling boundary: a hostile same-user
application that bypasses the broker can read an entry whose target it can compute. An
explicit local opt-in test records this observation with a second, ArcForges-free process.
An OS-enforced Windows adapter needs package identity (MSIX/AppContainer) and is not provided
here. No macOS keychain (code-signature access group), Linux secret-portal or Android keystore
adapter exists; `OsSecretStore.CreateForCurrentPlatform` fails closed with
`PlatformNotSupportedException` on any platform without a validated adapter, and never falls back
to files, preferences or memory.

The real OS round trip is an explicit local opt-in via `ARCFORGES_LOCAL_OS_SECRET_STORE=1`;
normal tests remain offline, and the two Windows-only tests are reported as skipped everywhere else,
including hosted CI. The Windows adapter's execution evidence is therefore a local opt-in run, not CI.

## Known limits

- Grant expiry uses the monotonic clock (`TimeProvider.GetTimestamp`), so a wall-clock change cannot extend
  or shorten a grant; `ConnectorSecretGrant.ExpiresAt` is informational.
- Revocation is immediate for every use that has not started. The host executor runs while its grant is locked,
  so revoking that one grant (sign-out) waits for an operation already in flight, which then completes; the
  executor contract therefore requires bounded runtime.
- Expired grants are evicted when the next grant is minted or on `RevokeAllConnectorGrants`; only the foreground
  human host can mint grants, so the table is host-bounded.
- The production project is classified AOT-compatible by policy, but no Native AOT publish of it runs in CI.
- There is no cross-process or concurrent-use test of the broker.
