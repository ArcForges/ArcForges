// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Supervisor;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Client;

/// <summary>Starts and checks only the local Node process carrying a selected or staged cohort.</summary>
public static partial class NodeUpdateLauncher
{
    private const string Systemctl = "/usr/bin/systemctl";

    public static string Executable(string installationRoot) =>
        Path.Combine(installationRoot, OperatingSystem.IsWindows() ? "arcforges.exe" : "arcforges");

    /// <summary>Keeps the native peer and the original Hello bound through subsequent update checks.</summary>
    public static IDisposable PinBoundSession(NodeSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        return session.PinConnection() ?? throw new IOException("node_update_connection_changed");
    }

    /// <summary>Starts a fenced candidate without changing systemd or the Windows service launcher.</summary>
    public static Process StartCandidate(NodeUpdateInstallation candidate, bool testMode)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        RequireTrustedManifest(candidate);
        var executable = Executable(candidate.Root);
        var start = new ProcessStartInfo(executable)
        {
            WorkingDirectory = candidate.Root,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add("node");
        start.ArgumentList.Add("run");
        if (testMode)
        {
            start.ArgumentList.Add(NodeLocations.TestModeOption);
        }

        return Process.Start(start) ?? throw new IOException("node_update_candidate_did_not_start");
    }

    /// <summary>Starts the selected version through the existing platform service owner.</summary>
    public static AutoStartResult StartManagedService(bool testMode)
    {
        if (!OperatingSystem.IsLinux())
        {
            return NodeAutoStart.StartExplicitly(testMode);
        }

        if (!NodeAutoStart.UserManagerAvailable() || NodeLocations.ForcedAutostart(testMode) == "setsid")
        {
            throw new IOException("node_update_systemd_user_manager_required");
        }

        return NodeAutoStart.StartSystemdService(testMode, Systemctl);
    }

    /// <summary>Moves an opted-in Windows startup entry only between verified installed cohorts.</summary>
    public static void RebindWindowsStartup(NodeUpdateInstallation previous, NodeUpdateInstallation selected, bool testMode)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var selectedSupervisor = Path.Combine(selected.Root, NodeAutoStart.SupervisorFileName);
        var app = NodeLocations.UpdateApplicationRoot(testMode);
        AutostartRegistration.Rebind(selectedSupervisor, current => IsAdmittedStartup(current, previous, app), WindowsStartupKey(testMode));
    }

    /// <summary>Verifies the existing Windows login launch can be stopped by parking its exact installed cohort.</summary>
    public static void RequireCanonicalWindowsStartup(NodeUpdateInstallation previous, bool testMode)
    {
        if (OperatingSystem.IsWindows())
        {
            var supervisor = Path.Combine(previous.Root, NodeAutoStart.SupervisorFileName);
            AutostartRegistration.RequireAbsentOrExact(supervisor, WindowsStartupKey(testMode));
        }
    }

    [SupportedOSPlatform("windows")]
    private static string WindowsStartupKey(bool testMode)
    {
        if (testMode && NodeLocations.EndpointOverride(testMode) is null)
        {
            throw new IOException("node_update_windows_startup_test_endpoint_required");
        }

        return testMode ? @"Software\ArcForges\Tests\Update\" + NodeLocations.InstanceKey(testMode) + @"\Run" : AutostartRegistration.RunKey;
    }

    private static bool IsAdmittedStartup(string registered, NodeUpdateInstallation previous, string appRoot)
    {
        if (NodeUpdateInstallationCustody.IsParked(appRoot, previous.ArchiveSha256))
        {
            if (!string.Equals(registered, Path.Combine(previous.Root, NodeAutoStart.SupervisorFileName), StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return VerifyParkedHolder(NodeUpdateInstallationCustody.ResolvePrevious(appRoot, previous));
        }

        if (!Path.IsPathFullyQualified(registered) || !string.Equals(Path.GetFileName(registered), NodeAutoStart.SupervisorFileName, StringComparison.OrdinalIgnoreCase)
            || (File.GetAttributes(registered) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
        {
            return false;
        }

        var root = Path.GetDirectoryName(registered)!;
        RequireTrustedManifest(previous with { Root = root });
        return SameFileBytes(registered, Path.Combine(previous.Root, NodeAutoStart.SupervisorFileName));
    }

    private static bool VerifyParkedHolder(NodeUpdateInstallation parked)
    {
        using var stream = OpenTrustedManifest(parked);
        using var manifest = JsonDocument.Parse(stream);
        if (!manifest.RootElement.TryGetProperty("files", out var files)
            || !files.TryGetProperty(NodeAutoStart.SupervisorFileName, out var expected))
        {
            return false;
        }

        var path = Path.Combine(parked.Root, NodeAutoStart.SupervisorFileName);
        if ((File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
        {
            return false;
        }

        using var holder = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(holder)) == expected.GetString();
    }

    /// <summary>Requires current native service custody of the exact responsive Node process.</summary>
    public static async Task RequireManagedProcessAsync(NodeUpdateInstallation cohort, Process node, AutoStartResult? started, bool testMode,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(cohort);
        ArgumentNullException.ThrowIfNull(node);
        if (OperatingSystem.IsWindows())
        {
            RequireHolder(cohort, node, started?.SupervisorProcessId);
            return;
        }

        if (!OperatingSystem.IsLinux() || !NodeAutoStart.UserManagerAvailable())
        {
            throw new IOException("node_update_systemd_user_manager_required");
        }

        var status = new ProcessStartInfo(Systemctl)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in new[] { "--user", "show", "--property=MainPID", "--value", "--", NodeLocations.NodeUnit(testMode) })
        {
            status.ArgumentList.Add(argument);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        using var observer = Process.Start(status) ?? throw new IOException("node_update_systemd_main_pid_unavailable");
        observer.StandardInput.Close();
        try
        {
            var pid = observer.StandardOutput.ReadToEndAsync(timeout.Token);
            var error = observer.StandardError.ReadToEndAsync(timeout.Token);
            await Task.WhenAll(pid, error, observer.WaitForExitAsync(timeout.Token)).ConfigureAwait(false);
            if (observer.ExitCode != 0 || !int.TryParse(pid.Result.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var main)
                || main != node.Id || node.HasExited)
            {
                throw new IOException("node_update_systemd_main_pid_mismatch");
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new IOException("node_update_systemd_main_pid_deadline");
        }
        finally
        {
            if (!observer.HasExited)
            {
                observer.Kill();
            }
        }
    }

    /// <summary>Checks a real local endpoint and the observed process executable before returning its ready connection.</summary>
    public static async Task<NodeSession> WaitForBoundReadyAsync(NodeUpdateInstallation cohort, bool testMode, int? expectedPid,
        CancellationToken cancellationToken)
    {
        var options = new NodeConnectOptions { TestMode = testMode, AutoStart = false, ReadinessTimeout = TimeSpan.FromSeconds(30) };
        var session = await NodeClient.WaitForReadyAsync(options, cancellationToken).ConfigureAwait(false);
        try
        {
            using var observed = ReadBoundProcess(session, cohort, expectedPid, allowVerifiedCopy: false);
            if (session.Hello.Node.State != NodeLifecycleState.Ready)
            {
                throw new IOException("node_update_candidate_not_healthy:" + session.Hello.Node.State);
            }

            await WaitForVersionIntegrityAsync(session, cohort, observed, cancellationToken).ConfigureAwait(false);

            return session;
        }
        catch
        {
            await session.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task WaitForVersionIntegrityAsync(NodeSession session, NodeUpdateInstallation cohort, Process process, CancellationToken cancellationToken)
    {
        using var pin = PinBoundSession(session);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            while (!process.HasExited)
            {
                using var call = session.Channel.Node.GetCapabilitiesAsync(new NodeServiceGetCapabilitiesRequest
                {
                    Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                }, deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: timeout.Token);
                var response = await call.ResponseAsync.ConfigureAwait(false);
                var integrity = response.Value?.Capabilities?.PlatformFacts.FirstOrDefault(fact => fact.Name == "version_integrity")?.Value;
                if (integrity == "verified")
                {
                    RequireTrustedManifest(cohort);
                    return;
                }

                if (response.Error is not null || integrity?.StartsWith("mismatch", StringComparison.Ordinal) is true)
                {
                    throw new IOException("node_update_version_integrity_refused:" + (integrity ?? response.Error?.Code));
                }

                await Task.Delay(TimeSpan.FromMilliseconds(250), timeout.Token).ConfigureAwait(false);
            }

            throw new IOException("node_update_process_exited_before_integrity_check");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new IOException("node_update_version_integrity_deadline");
        }
    }

    internal static void RequireTrustedManifest(NodeUpdateInstallation cohort)
    {
        using var stream = OpenTrustedManifest(cohort);
    }

    internal static FileStream OpenTrustedManifest(NodeUpdateInstallation cohort)
    {
        var manifest = Path.Combine(cohort.Root, "digests.json");
        if ((File.GetAttributes(manifest) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new IOException("node_update_version_manifest_untrusted");
        }

        var stream = File.OpenRead(manifest);
        try
        {
            if (stream.Length > 4 * 1024 * 1024 || Convert.ToHexStringLower(SHA256.HashData(stream)) != cohort.DigestManifestSha256)
            {
                throw new IOException("node_update_version_manifest_changed");
            }

            stream.Position = 0;
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    /// <summary>Opens the Node descriptor's exact process only if it is the admitted executable.</summary>
    public static Process ReadBoundProcess(NodeSession session, NodeUpdateInstallation cohort, int? expectedPid, bool allowVerifiedCopy)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(cohort);
        using var pin = PinBoundSession(session);
        var descriptor = EndpointDescriptor.TryRead(NodeLocations.EndpointDescriptorFile(session.Endpoint.DataRoot))
            ?? throw new IOException("node_update_descriptor_missing");
        if (descriptor.ProcessId != session.ServerProcessId || (expectedPid is int pid && descriptor.ProcessId != pid)
            || descriptor.NodeId != IdText.Format(session.Hello.Node.Node.NodeId)
            || descriptor.Endpoint != session.Endpoint.Endpoint.Address)
        {
            throw new IOException("node_update_endpoint_identity_mismatch");
        }

        var process = Process.GetProcessById(descriptor.ProcessId);
        try
        {
            _ = process.SafeHandle;
            var started = new DateTimeOffset(process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds();
            var expectedExecutable = Executable(cohort.Root);
            var actual = process.MainModule?.FileName;
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (actual is null || started != descriptor.ProcessStartUnixMs
                || (!allowVerifiedCopy && !string.Equals(actual, expectedExecutable, comparison))
                || !SameFileBytes(OperatingSystem.IsLinux() ? $"/proc/{process.Id}/exe" : actual, expectedExecutable)
                || process.HasExited)
            {
                throw new IOException("node_update_running_cohort_mismatch");
            }

            return process;
        }
        catch
        {
            process.Dispose();
            throw;
        }
    }

    /// <summary>Stops only the service process. Per-Run ownership survives an ordinary service shutdown.</summary>
    public static async Task StopBoundAsync(NodeSession session, Process process, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(process);
        using var pin = PinBoundSession(session);
        if (process.Id != session.ServerProcessId || process.HasExited)
        {
            throw new IOException("node_update_shutdown_target_changed");
        }
        var command = CommandIds.New();
        var request = new NodeServiceStopNodeRequest
        {
            Meta = new RequestMeta { CommandId = command, CorrelationId = CommandIds.New() },
            Reason = "verified Node cohort update",
            TimeoutMs = 15_000,
        };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        using var call = session.Channel.Node.StopNodeAsync(request, deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: timeout.Token);
        var result = await call.ResponseAsync.ConfigureAwait(false);
        if (result.Value?.Receipt is not { Effect: EffectCertainty.Happened } receipt || !command.Equals(receipt.CommandId))
        {
            throw new IOException("node_update_shutdown_unconfirmed:" + result.Error?.Code);
        }

        await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
    }

    private static bool SameFileBytes(string actual, string expected)
    {
        using var actualFile = File.OpenRead(actual);
        using var expectedFile = File.OpenRead(expected);
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(actualFile), SHA256.HashData(expectedFile));
    }

    private static void RequireHolder(NodeUpdateInstallation cohort, Process node, int? expectedPid)
    {
        if (QueryProcess(node.SafeHandle, 0, out var identity, (uint)(IntPtr.Size * 6), out _) != 0
            || identity.ProcessId != node.Id || identity.ParentId is <= 0 or > int.MaxValue
            || (expectedPid is int pid && identity.ParentId != pid))
        {
            throw new IOException("node_update_windows_supervisor_identity_mismatch");
        }

        using var holder = Process.GetProcessById((int)identity.ParentId);
        var expected = Path.Combine(cohort.Root, NodeAutoStart.SupervisorFileName);
        if (holder.HasExited || node.HasExited || holder.StartTime > node.StartTime
            || !string.Equals(holder.MainModule?.FileName, expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("node_update_windows_supervisor_identity_mismatch");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        private nint _exitStatus;
        private nint _peb;
        private nint _affinity;
        private nint _priority;
        public nint ProcessId;
        public nint ParentId;
    }

    [LibraryImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess")]
    private static partial int QueryProcess(SafeProcessHandle process, int informationClass, out ProcessBasicInformation information,
        uint informationBytes, out uint bytesWritten);
}
