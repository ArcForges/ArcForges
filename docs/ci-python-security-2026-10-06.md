# CI Python security admission, 2026-10-06

GOV.23 adopts the exact virtualenv 21.5.1-to-21.7.13 patch retained in [Dependabot PR 116](https://github.com/ArcForges/DesktopPlatform/pull/116), source 57801a0e67799b6d695f0bdc2428e5ec31f09341. The original branch/history remains unchanged. [Upstream GHSA-p58f-9548-mpm2](https://github.com/pypa/virtualenv/security/advisories/GHSA-p58f-9548-mpm2) identifies bash/fish activation-script path command injection affecting <=21.7.12 and fixed by 21.7.13; upstream publication was 2026-09-18, and this repository diagnosed the vulnerable pin on 2026-10-06.

The preserved PR already records the exact defect: [repository-hooks job 110537264414](https://github.com/ArcForges/DesktopPlatform/actions/runs/36912180246/job/110537264414) failed `pip` with `ResolutionImpossible` for python-discovery 1.4.3 versus virtualenv 21.7.13 requiring >=1.6. Its separate [licence job 110537264366](https://github.com/ArcForges/DesktopPlatform/actions/runs/36912180246/job/110537264366) refused changed inputs without admission. Old failures are diagnosis evidence, never current-head CI authority.

The exact preserved patch alone is insufficient: actual 21.7.13 wheel METADATA requires `python-discovery>=1.6`, while the existing requirement is 1.4.3. The minimum 1.6.0 wheel requires only `filelock>=3.15.4`; existing 3.29.5 satisfies it. For pinned Python 3.14.7, virtualenv also requires `distlib>=0.3.7,<1`, `filelock>=3.24.2,<4` and `platformdirs>=3.9.1,<5`, satisfied by existing 0.4.3/3.29.5/4.10.0. Older-Python conditional filelock/typing-extensions requirements are inactive. All remaining coordinates and .NET/native/toolchain versions are preserved.

Both distribution identities were checked against primary [virtualenv PyPI 21.7.13 metadata](https://pypi.org/pypi/virtualenv/21.7.13/json) and [python-discovery PyPI 1.6.0 metadata](https://pypi.org/pypi/python-discovery/1.6.0/json). The actual bounded wheel downloads were SHA256/size verified once, and exact METADATA/full LICENSE bytes inspected without installation. No external implementation or wheel is copied into capability packages. The existing CI `pip install --require-hashes` uses the complete pinned requirement closure; existing security/release checks remain enabled.

| Coordinate | Wheel SHA256 | Source distribution SHA256 | License |
|---|---|---|---|
| virtualenv/21.7.13 | 1bea5af7463f59c4719db48fe739579a2a4f569c96f26c086edda85c96da9f59| 0355558b6f33619aab31347e43643b0ebc97f61ea3acf617b2b69e1f8a843d11| MIT |
| python-discovery/1.6.0 | d4e244cf17b8b29819ed78003d55fbacf86eda23425b075454fff9271b79377a| 6393b4eae1be8b2182670635e7baff89ac21cb9f8e86fd1ff40c7b1144febb4c| MIT |

Immutable policy history retains old 21.5.1/1.4.3 coordinates and every prior receipt. The new GOV.23 receipt chains from the active producer admission and binds the actual requirement/metadata/licence closure. Focused negatives reject old discovery, omitted/mutated distributions and unauthorized historical hash changes. Exact-head independent review, applicable hosted CI and normal publication receipts remain separate delivery gates; no mocked tool behavior is claimed as actual CI success.
