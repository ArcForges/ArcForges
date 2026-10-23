// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using Tmds.DBus.Protocol;

namespace ArcForges.Node.Platform.Linux;

/// <summary>
/// An adoption container on Linux (04 section 10): the transient scope <c>arcforges-x-&lt;attempt&gt;.scope</c> in the node's slice, into
/// which the user manager moved the adopted process. Its later children stay in the scope's cgroup; the scope ends when it is empty. The
/// scope belongs to the user manager, not to the node, so it survives a node restart and is re-opened by name.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class LinuxAdoptedScope(LinuxExecutionPlatform platform, string unit, string directory) : IAdoptedContainer
{
    /// <inheritdoc />
    public string ContainerName => unit;

    /// <inheritdoc />
    public IReadOnlyList<int> Processes() => Directory.Exists(directory) ? ProcFs.Procs(directory) : [];

    /// <inheritdoc />
    public void Terminate()
    {
        try
        {
            platform.Manager.KillUnit(unit, "all", Libc.SigKill);
        }
        catch (DBusErrorReplyException) when (!Directory.Exists(directory))
        {
            // The scope already ended (its last process exited).
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
    }
}
