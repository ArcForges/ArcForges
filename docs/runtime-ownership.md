# Runtime and source ownership

WP00.05 implements the [current Design profile](https://github.com/ArcForges/ArcForges-Design/blob/e2dd78058ce2d4bd1a8434a34d049bbc1158eacb/docs/architecture/30-runtime-and-source-ownership-policy.md).
The registry is `eng/policy/runtime-ownership.json`. Nine implementation owners
are independent; Design is documentation authority, and ArcChat is an embedded
assistant/companion feature. Policy does not create another runtime package.

```text
python -m unittest discover -s eng -p test_runtime_ownership.py -v
python eng/runtime_ownership.py --evaluate-managed
```

Default verification reads this checkout and fetches the eight other owners at
their exact recorded commits into disposable isolated checkouts. It validates the
fixed Design identity, real historical extraction tree, all current project and
source inventories, declared runtime configuration, and the Contracts naming scan.
It never builds adjacent source. Contracts and Mobile do not import AGPL tooling.
Pass all nine `--repository Owner=absolute-root` arguments for a fresh family audit;
`--design-root` may use a local Design Git checkout containing the bound commit.
Reports retain actual source commit/dirty state, file/project counts, policy digest
and findings under ignored `artifacts/evidence/`. A current family audit is required
after merges; immutable snapshots alone cannot establish that current main conforms.

The project-role inventory covers every existing build manifest, including tooling,
tests, native IDE adapters and runtime-package containers. Source files additionally
require the existing complete provenance assignment. Licence/reference checks remain
independent. Registered old product trees cannot be restored into DesktopPlatform;
the excluded Notes canvas/slides paths remain rejected even with a new inventory row.

The AOT source check follows explicit local imports and nearest automatic directory
build files, rejects false/conditional required declarations and unknown dynamic
imports, and distinguishes libraries, hosts and build/test programs. It does not
implement an MSBuild evaluator. `--evaluate-managed` additionally invokes the pinned
SDK only for this owner's production hosts/libraries in Debug and Release; their
actual evaluated property must agree. Existing native/managed package-consumer CI
continues to prove execution. JavaScript IDE adapters cannot inherit .NET runtime
properties. The runtime check parses project/dependency/deployment inputs, not
arbitrary historical prose; its bounded checks do not prove whole-program behavior.

The registered AI Hello Workflow requires its direct Workers AI binding, one exact
Workflow and no alternate Container/environment. Cloud has one Container bridge,
and Web has React static assets. The Kotlin Android bootstrap keeps its observed
prerelease identity, JVM 21 and development-only preview. These registrations must
be reviewed when their scheduled product work changes the actual structure.
They never authorize another agent runtime, production Node host, iOS deliverable,
old database provider, or unregistered project/source owner.

## Reviewed claim corrections

Reviewed on 2026-09-20 against the pinned Design authority. Each correction preserves
existing Hello/probe APIs, published package identities and runtime behavior.

| Owner and path | Previous claim | Accepted replacement and verification |
|---|---|---|
| Design WP00.05 | Ten implementation repositories | Nine owners; Design remains documentation authority. Full corpus preview and Design PR29 review. |
| DesktopPlatform `docs/platform-bootstrap.md` | Ten-repository completion boundary; original Design pin could appear current | Nine current owners; extraction results explicitly revision-bound. Historical results preserved. |
| DesktopPlatform ContentSandbox project comment | Four desktop heads and removed layout document | Parent-bound Native AOT helper scaffold; architecture27 and WP11/13 own complete behavior. Source property/evaluated build and existing CI checked. |
| Contracts npm proto/API-client READMEs | React Native/Hermes remained a mobile delivery target | TypeScript Web; Android uses generated Kotlin gRPC-Web. Packaged README bytes and published candidates are checked after merge. |
| Contracts `docs/architecture.md` | Native gRPC could appear an alternative current public business transport | Binary gRPC-Web; existing native Hello fixtures explicitly compatibility-only. No API or fixture removal. |
| Contracts `docs/bootstrap-plan.md` | Original RN direction could escape its historical scope | Source-bound original plan explicitly reviewed as historical; results preserved, current authority linked. |
| Cloud README/bootstrap scope | PostgreSQL remained a future target | D1 business transactions; current Hello remains stateless. Existing AOT image/real protocol and main Cloudflare checks apply. |
| AI README | Cloud owned PostgreSQL transactions | Cloud owns D1 transactions; sole Workflow unchanged. Source/bundle tests and main real model/tool/model gate remain required. |

The registry records old monorepo groups against extraction commit
`99bfe7d695ed0d65a0d035af7d219fc9b86100f5`, together with their current owners and
dispositions. Eleven shared placeholders remain non-packable, and the helper is
still a scaffold. Full business schemas, assistant implementations, all native
functional families/RIDs, four Web surfaces, Android identity/toolchain migration
and commercial operation remain at their named stages. Existing snapshot evidence
does not close those gates or require recreating already absent legacy source.

## Reduced-family adoption (GOV.18)

The active runtime policy enumerates the seven retained owners only. The DesktopPlatform project inventory tracks the retained image ABI and current owned managed projects. Removed repository entries are not fetched or audited as current owners. Historical source identities and retired-scaffold evidence remain historical; product functionality is not inferred.
