// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.NativeInterop;

namespace ArcScope.Native;

public static class MdfNativeSmoke
{
    public static NativeProbeResult Verify() => NativeSmoke.VerifyMdf();
}
