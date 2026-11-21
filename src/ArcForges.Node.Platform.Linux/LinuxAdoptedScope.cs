// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
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
    public IReadOnlyList<int> Processes()
    {
        try
        {
            var members = new List<int>();
            foreach (var line in File.ReadLines(Path.Combine(directory, "cgroup.procs")))
            {
                if (!int.TryParse(line, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid <= 0)
                {
                    throw new LegacyCustodyUnavailableException("The recorded scope reported invalid membership.");
                }

                members.Add(pid);
            }

            if (members.Count == 0 && !File.ReadLines(Path.Combine(directory, "cgroup.events")).Contains("populated 0", StringComparer.Ordinal))
            {
                throw new LegacyCustodyUnavailableException("The recorded scope's whole-tree membership is not confirmed empty.");
            }

            return members;
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            try
            {
                if (platform.Manager.GetUnit(unit) is null)
                {
                    return [];
                }
            }
            catch (Exception queryError) when (queryError is DBusExceptionBase or TimeoutException or IOException or InvalidOperationException)
            {
                throw new LegacyCustodyUnavailableException("The systemd user manager did not confirm the recorded scope's departure.", queryError);
            }

            throw new LegacyCustodyUnavailableException("The recorded scope is still loaded but its membership is unavailable.", exception);
        }
        catch (Exception exception) when (exception is IOException and not LegacyCustodyUnavailableException or UnauthorizedAccessException)
        {
            throw new LegacyCustodyUnavailableException("The recorded scope's membership could not be read.", exception);
        }
    }

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
    public string Abandon()
    {
        // AbandonScope: the user manager stops managing the scope and never stops it; its processes keep running, in that cgroup.
        try
        {
            platform.Manager.AbandonScope(unit);
            return $"the adoption scope {unit} was abandoned: the user manager no longer manages it, and its processes keep running, not adopted";
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException or InvalidOperationException)
        {
            return $"the adoption scope {unit} could not be abandoned ({exception.Message}): its processes keep running in it, not adopted";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
    }
}
