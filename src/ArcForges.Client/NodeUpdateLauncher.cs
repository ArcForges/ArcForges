// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Client;

/// <summary>Starts and checks only the local Node process carrying a selected or staged cohort.</summary>
public static class NodeUpdateLauncher
{
    public static string Executable(string installationRoot) =>
        Path.Combine(installationRoot, OperatingSystem.IsWindows() ? "arcforges.exe" : "arcforges");

    /// <summary>Starts a fenced candidate without changing systemd or the Windows service launcher.</summary>
    public static Process StartCandidate(NodeUpdateInstallation candidate, bool testMode)
    {
        ArgumentNullException.ThrowIfNull(candidate);
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

            return session;
        }
        catch
        {
            await session.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Opens the Node descriptor's exact process only if it is the admitted executable.</summary>
    public static Process ReadBoundProcess(NodeSession session, NodeUpdateInstallation cohort, int? expectedPid, bool allowVerifiedCopy)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(cohort);
        var descriptor = EndpointDescriptor.TryRead(NodeLocations.EndpointDescriptorFile(session.Endpoint.DataRoot))
            ?? throw new IOException("node_update_descriptor_missing");
        if ((expectedPid is int pid && descriptor.ProcessId != pid)
            || descriptor.NodeId != IdText.Format(session.Hello.Node.Node.NodeId)
            || descriptor.Endpoint != session.Endpoint.Endpoint.Address)
        {
            throw new IOException("node_update_endpoint_identity_mismatch");
        }

        var process = Process.GetProcessById(descriptor.ProcessId);
        try
        {
            var started = new DateTimeOffset(process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds();
            var expectedExecutable = Executable(cohort.Root);
            var actual = process.MainModule?.FileName;
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (process.HasExited || started != descriptor.ProcessStartUnixMs || actual is null
                || (!string.Equals(actual, expectedExecutable, comparison) && (!allowVerifiedCopy || !SameFileBytes(actual, expectedExecutable))))
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
        using var pin = session.Channel.PinConnection(session.Channel.ConnectionGeneration)
            ?? throw new IOException("node_update_connection_changed");
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
}
