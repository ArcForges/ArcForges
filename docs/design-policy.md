# Design policy export

DesktopPlatform validates a reviewed immutable ArcForges-Design documentation commit and exports its glossary and invariant mapping. `eng/policy/design-source.json` pins that commit, the graph and policy source hashes, and the Markdown corpus digest. The exporter executes no Design programs or hooks and reads no sibling implementation source.

The graph validator in `eng/design_graph.py` adapts the pure Plan delivery validator and renderer at the source identity recorded in `eng/provenance/records/plan-delivery-graph-r1.json`. It checks typed start/completion events, obligation coverage, adoption slices, substitute replacement, repository/lane identities and freshly generated Design-owned views. Active invariant owners derive from tasks' mapped obligation packages. It also checks required work-package sections and each owned final evidence row. Retired serial tables and package-edge counts are not execution authorities.

## Reviewed refresh

Preview a proposed Design worktree with `python eng/design_policy.py --design-root <absolute-root> --preview`. After the Design PR merges, record its exact commit and normalized source hashes in the pin; then run `python eng/design_policy.py --design-root <clean-pinned-root> --refresh` and independently run the same command without `--refresh`. CI fetches that exact documentation commit in isolation. Any source identity, occurrence classification, generated view or export drift fails.

GOV.18 migrates the graph checker, reduces policy ownership and performs the initial repin. GOV.14 retains broader current specification-integrity acceptance; the migration does not close that task. The reduced export currently contains107 term rows (116 names),406 invariant rows and15 contextual forbidden aliases. These are planned verification records, not implemented behavior or commercial evidence; current counts always derive from the pinned sources.

The independent small delivery-graph fixtures mutate edges, obligation coverage, substitute replacements, owners, generated views and work-package evidence. Existing exact export, glossary, citation, anchor, occurrence, dirty-tree and wrong-pin rejection fixtures remain. Run `python -m unittest discover -s eng -p test_design_policy.py -v`. Retained CI also compiles and packages the admitted Windows/Linux outputs; no runtime consumer or public-download verification cycle is added.

Contracts owns canonical naming rules and scanner publication. A consumer pins its immutable naming candidate, and the derived declaration binds the exact Design commit, glossary source hash and forbidden-alias array digest. Contextual aliases never become an independent global substring registry.
