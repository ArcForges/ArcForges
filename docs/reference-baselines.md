# WP00.04 reference planning inputs

The [accepted registration profile](https://github.com/ArcForges/ArcForges-Design/blob/f5ef5d56dba6e7ecbe49a4ff47163bc548b94c8c/docs/assurance/reference-baseline-registration.md)
assigns this registry, verifier and CI to DesktopPlatform. The five matrix IDs are
assistant, notes, scope, slate and distribution. Matrix prose remains in Design;
reference source is never copied or executed. The entry point binds the exact
provenance metadata digest, which binds its independent Design pin, matrix hashes,
six full source commits, review and dated packaged directory/notice observation.
The existing glossary pin and exports have separate inputs and remain unchanged.

```text
python -m unittest discover -s eng -p test_reference_baselines.py -v
python eng/reference_baselines.py
```

The default obtains isolated bare snapshots from registered origins, verifies
commit types and document hashes/row IDs, and retains a report at
`artifacts/evidence/reference-baselines.json`. CI runs both commands on Windows
and Linux. It explicitly reports the packaged input as registered but not
re-observed; the local packaged tree is not a hosted-CI dependency. This does not
claim packaged bytes were tested or authorize binary execution.

For a local acceptance run supply every source explicitly: `--source design=PATH`
and `--source s1=PATH` through `--source s6=PATH`. Map the IDs using
`eng/provenance/reference-inputs.json`; origins must match. Add
`--packaged-root PATH` to re-observe the real packaged tree. The observer lists
immediate product-directory children and reads only the seven registered text
notices. It rejects links, changed layout, missing versioned installer names and
changed notices. No executable/library bytes are read. The observation date is
2026-09-20; it is not evidence for historical packaged bytes at the earlier matrix
review date. The registration declares only this narrow observable boundary.

Add `--drift s2 --candidate HEAD` for a Notes-source drift dry run, or select
another registered source and a resolvable candidate revision. The command fixes
the candidate to a full commit, compares tree metadata (including object IDs),
and reports added/removed/modified paths. Working changes are reported separately;
they never become part of the accepted commit. The report reads no source patch
and does not approve a changed reference. Matrix/source scope changes are reviewed
under the linked profile by the consuming Architecture/Product Owner and Licensing
and Provenance Owner before consumption. Later maintenance owners remain in the
registry; no later substep is completed here.

The 2026-09-20 local run verified five matrices, six commits and all seven notice
hashes against the real directories. The s2 dry run compared its bound commit with
the identical current commit and found no source delta. s1, s5 and s6 had existing
unreviewed local edits, separately recorded and excluded from fixed inputs.
They do not change the registered historical objects and are not accepted new
reference material. The source repositories were not modified. Twelve initial
failure/behavior test groups use real disposable Git commits and independent
expected add/modify/delete results; they also cover schema, hash, origin, row and
packaged-observation failures. PR and post-merge receipts provide the final CI
and commit identities; these local facts alone do not establish merge completion.

Keep registry updates reviewed and versioned. Contracts admits only the exact
metadata digest for its two reference-name exceptions; changed bytes need a new
reviewed registration before the family naming scan passes. Metadata is authored
identity/provenance information, not reused source or a second naming authority.
No capability package, runtime behavior or commercial readiness follows from
planning-input verification.

## Reduced-family adoption (GOV.18)

The active registry selects assistant, scope and distribution only. The immutable original provenance metadata retains all historical registrations unchanged; verification resolves only the two Git references consumed by active matrices. Removed Notes/Slate sources are not fetched. Optional packaged-reference inspection remains read-only and explicitly requested; no binary is executed or unpacked.
