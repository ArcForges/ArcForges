<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# ArcForges.Security.CapabilityEnforcement

This managed package composes typed capability invocation with the current
security decision pipeline and the final-owner execution gate. An admission is
bound to its exact invocation and owner, spent once, and rechecked at execution.
Callers supply real evidence and current authority; there is no default allow
or success-only owner implementation. Capability descriptors and actor chains
remain evidence, rather than authorization.

PLT.59 admits the existing implementation to normal exact-version publication
alongside ArcForges.Security and ArcForges.Capabilities using compatible
production Contracts peers. Shared AI assistant invocations use the same owner,
permission, approval, lease, audit and lifecycle rules. Product and OS acceptance
remain with the consuming application and PLT.46.
