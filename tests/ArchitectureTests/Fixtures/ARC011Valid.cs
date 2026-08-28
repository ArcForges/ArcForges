// SPDX-License-Identifier: AGPL-3.0-only
// ARC-011 compliant sample. This file participates in compilation; its violating twin is
// ARC011Violation.cs.txt, which is stored as text and compiled only at test time.

namespace ArcForges.Tests.ArchitectureTests.Fixtures;

internal sealed class OpaqueMediaHandle : System.Runtime.InteropServices.SafeHandle
{
    public OpaqueMediaHandle() : base(System.IntPtr.Zero, ownsHandle: true) { }

    public override bool IsInvalid => handle == System.IntPtr.Zero;

    protected override bool ReleaseHandle() => true;
}
