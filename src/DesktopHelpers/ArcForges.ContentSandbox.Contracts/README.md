# ArcForges.ContentSandbox.Contracts

A thin facade over the generated `ArcForges.Contracts.LocalRpc.Sandbox` and `.Platform` bindings (CON.04, CON.05). It owns no authored or
generated wire type. It fixes what the parent and the helper must agree on beyond the schema: the contract-set digest of the launch, the
control methods, the profile limits of an invocation, the mapping of the generated slot grant, seal and acknowledgement records onto the
`ArcForges.LocalRpc` brokered-data records, and the one private launch frame the parent writes to the inherited standard input of the helper
(its closed resource inventory, identity, budget and the one-use bootstrap resource).

PLT.59 admits this implemented managed protocol package to normal lockstep
publication. The executable, parser RID packages and release trust are separate
NAT.22/NAT.25 producers. PLT.46 retains complete product and OS acceptance.
