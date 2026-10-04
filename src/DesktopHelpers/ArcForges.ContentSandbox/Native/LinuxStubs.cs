// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;

namespace ArcForges.ContentSandbox.Native;

internal static class LinuxEnforcement
{
    internal static bool ApplyAndVerify(ContentSandboxLaunchFrame frame) => false;
}

internal static class LinuxResources
{
    internal static HelperResources Open(ContentSandboxLaunchFrame frame) => throw new PlatformNotSupportedException("Not yet.");
}
