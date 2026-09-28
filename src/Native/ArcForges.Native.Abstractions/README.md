# ArcForges.Native.Abstractions

Shared status, opaque handle ownership, and pack-8 layout declarations for the retained ArcForges C ABI families. The Image package provides the source-generated bindings. This package contains no native binary and does not implement image, instrument, or PDF operations.

The existing image probe exports remain ABI 1.0. Functional image, instrument, and PDF libraries advertise ABI 1.1 when those exports are delivered. Native handles are nonzero, process-local tokens owned through `NativeSafeHandle`; they are not pointers, durable identifiers, or wire values. Calls on one handle are single-caller; cancellation may be signalled concurrently. Closing drains borrowed calls before invalidating the handle generation, while children retain their parent object until released.

Pin the exact package version centrally and commit package locks.
The runtime package supplies app-local DLLs and a hash manifest. Loading never searches PATH or the
current working directory. Final product installation owns signing, read-only application paths and
any later hostile-content sandbox. Current native queries do not parse untrusted content.
