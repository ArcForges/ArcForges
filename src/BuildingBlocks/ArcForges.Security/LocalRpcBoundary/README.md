<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# ArcForges.Security.LocalRpcBoundary

This managed package applies current security decisions to parent-owned generated
local RPC calls. A transport identity, registration or actor snapshot never
authorizes an operation by itself. The owner composes real current authority,
permission, approval, lease, resource and execution dependencies; refusal,
cancellation and expired/foreign evidence do not become successful calls.

PLT.59 admits the existing implementation to the exact-version lockstep
publisher. The package depends on ArcForges.Security and ArcForges.LocalRpc,
with the admitted production Foundation contract peer. Publication does not
certify a particular child process or OS isolation profile. PLT.46 retains
complete product and OS acceptance.
