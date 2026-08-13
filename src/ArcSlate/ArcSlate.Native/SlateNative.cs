// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.NativeInterop;

namespace ArcSlate.Native;

public static class SlateNativeSmoke
{
    public static IReadOnlyList<NativeProbeResult> Verify() =>
        [NativeSmoke.VerifyOtio(), NativeSmoke.VerifyColor(), NativeSmoke.VerifyImage()];
}
