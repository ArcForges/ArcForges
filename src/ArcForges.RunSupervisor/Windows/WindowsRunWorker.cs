// SPDX-License-Identifier: AGPL-3.0-only

using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Node.Platform.Windows;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.RunSupervisor.Protocol;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.RunSupervisor;

[SupportedOSPlatform("windows")]
internal static class WindowsRunWorker
{
    internal static void RequireControlPeer(RunLaunchSpec spec, SafePipeHandle pipe)
    {
        if (spec.LauncherPath is null || !Path.IsPathFullyQualified(spec.LauncherPath)
            || !long.TryParse(spec.LauncherCreationIdentity, NumberStyles.None, CultureInfo.InvariantCulture, out var creation))
        {
            throw new InvalidDataException("The Windows Run manifest lacks an exact Node process identity.");
        }

        WindowsMxcProcess.RequirePeer(pipe, localIsServer: true, spec.LauncherProcessId, creation, spec.LauncherPath);
    }

    internal static ValueTask<RunOwnerIdentity> ReadyAsync(RunLaunchSpec spec, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        WindowsMxcProcess.SuppressOwnerErrorDialogs();
        if (!StringComparer.OrdinalIgnoreCase.Equals(WindowsMxcProcess.CurrentImagePath(), Path.GetFullPath(spec.SupervisorPath))
            || spec.BoundaryDescriptor != "windows-anonymous-job:" + spec.OwnerId)
        {
            throw new InvalidDataException("The Windows owner image or prepared Run boundary identity differs.");
        }

        using var control = WindowsMxcPathLease.Open(spec.ControlDirectory, directory: true, privateObject: true);
        using var launch = WindowsMxcPathLease.Open(RunWire.LaunchPath(spec), directory: false, privateObject: true);
        return ValueTask.FromResult(new RunOwnerIdentity(spec.OwnerId, WindowsMxcProcess.BootIdentity(), Environment.ProcessId,
            WindowsMxcProcess.CurrentCreationFileTime().ToString(CultureInfo.InvariantCulture), spec.ControlEndpoint,
            spec.BoundaryDescriptor, spec.ProfileId, spec.ProfileVersion, spec.Epoch));
    }

    internal static async ValueTask<IRunWorkerSession> StartAsync(RunLaunchSpec spec, RunRelease release, CancellationToken cancellationToken)
    {
        WindowsMxcJob? aggregate = null;
        WindowsMxcJob? payload = null;
        WindowsMxcStage? installed = null;
        WindowsRunPathBindings? paths = null;
        WindowsMxcPathLease? control = null;
        WindowsMxcPathLease? policy = null;
        WindowsMxcPathLease.PrivateFileIdentity? createdPolicy = null;
        string? policyPath = null;
        WindowsRunIo? io = null;
        RunOutputCapture? capture = null;
        LaunchedProcess? executor = null;
        var phase = "windows_aggregate_accept";
        var mayHaveResumed = false;
        var handedOff = false;
        try
        {
            aggregate = WindowsMxcJob.Accept(release.NativeBoundaryHandle
                ?? throw new InvalidDataException("The Windows owner received no Job capability."), WindowsRunLauncher.Limits(spec));
            phase = "windows_mxc_installation";
            installed = WindowsMxcStage.Open(spec);
            phase = "windows_mxc_bound_paths";
            paths = WindowsRunPathBindings.Open(spec);
            phase = "windows_mxc_policy";
            control = WindowsMxcPathLease.Open(spec.ControlDirectory, directory: true, privateObject: true);
            policyPath = Path.Combine(control.Path, "mxc-request.json");
            var policyBinding = WindowsRunPolicy.Write(spec, policyPath, identity => createdPolicy = identity);
            policy = WindowsMxcPathLease.Open(policyPath, directory: false, privateObject: true);
            policy.RequirePrivateFileIdentity(createdPolicy!.Value);
            WindowsRunPolicy.RequireBinding(spec, policy, policyBinding);
            phase = "windows_payload_boundary";
            payload = WindowsMxcJob.Create(limits: null);
            phase = "windows_mxc_preflight";
            await WindowsMxcPreflight.CheckAsync(installed, policy.Path, control.Path, aggregate, payload, cancellationToken).ConfigureAwait(false);
            WindowsRunPolicy.RequireBinding(spec, policy, policyBinding);

            cancellationToken.ThrowIfCancellationRequested();
            phase = "windows_terminal_or_pipes";
            io = WindowsRunIo.Create(spec.TerminalMode == RunTerminalMode.Interactive, spec.Columns, spec.Rows);
            phase = "windows_output_spool";
            capture = RunOutputCapture.Create(spec);
            paths.RequireStable();
            phase = "windows_mxc_create";
            executor = WindowsMxcProcess.CreateSuspended(installed.Executor, ["--config", policy.Path], installed.Directory,
                WindowsMxcProcess.TrustedEnvironment(control.Path), payload, io.ConsoleHandle, io.Standard);
            io.ReleaseRemoteEnds();
            var executorBirth = WindowsMxcProcess.RequireIdentity(executor, installed.Executor);
            phase = "windows_payload_membership";
            payload.RequireMember(executor);
            payload.RequireLimits(limits: null);
            var payloadMembers = payload.RequireOnly(executor.ProcessId);
            phase = "windows_aggregate_membership";
            aggregate.RequireMember(executor);
            var limits = WindowsRunLauncher.Limits(spec);
            aggregate.RequireLimits(limits);
            // ConPTY's native host can also be a member. The aggregate readback includes it and
            // finalization still has to prove that only this exact owner remains.
            var aggregateMembers = aggregate.Observe();
            if (!aggregateMembers.ProcessIds.Contains(Environment.ProcessId)
                || !aggregateMembers.ProcessIds.Contains(executor.ProcessId))
            {
                throw new InvalidDataException("The Run aggregate is missing its trusted owner or suspended executor.");
            }

            phase = "windows_pre_resume_evidence";
            var evidence = new WindowsRunEvidence(spec, policyBinding, executor.ProcessId, executorBirth);
            evidence.WritePrepared(limits, aggregateMembers, payloadMembers);
            paths.RequireStable();
            cancellationToken.ThrowIfCancellationRequested();
            phase = "windows_mxc_resume";
            mayHaveResumed = true;
            WindowsMxcProcess.Resume(executor);
            var session = new WindowsRunSession(aggregate, payload, executor, io, installed, control, policy, paths, evidence, capture);
            handedOff = true;
            return session;
        }
        catch (Exception error) when (error is IOException or Win32Exception or InvalidDataException or JsonException
            or ArgumentException or InvalidOperationException or KeyNotFoundException or FormatException or OperationCanceledException or UnauthorizedAccessException)
        {
            var native = error is RunNativeException backend ? backend.NativeCode : WindowsRunLauncher.NativeCode(error);
            var empty = false;
            capture?.Dispose();

            try
            {
                if (payload is not null && !payload.Observe().Empty)
                {
                    payload.Terminate();
                    _ = await payload.WaitForDrainAsync(null, TimeSpan.FromSeconds(8), CancellationToken.None).ConfigureAwait(false);
                }

                if (io is not null)
                {
                    io.CloseInput();
                    var outputDrain = io.Output.CopyToAsync(Stream.Null, 16 * 1024, CancellationToken.None);
                    var errorDrain = io.Error?.CopyToAsync(Stream.Null, 16 * 1024, CancellationToken.None) ?? Task.CompletedTask;
                    io.ReleaseRemoteEnds();
                    await Task.WhenAll(io.CloseConsoleAsync(), outputDrain, errorDrain)
                        .WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
                }

                if (aggregate is not null)
                {
                    _ = await aggregate.WaitForDrainAsync(Environment.ProcessId, TimeSpan.FromSeconds(8), CancellationToken.None).ConfigureAwait(false);
                    policy?.Dispose();
                    policy = null;
                    if (createdPolicy is { } owned)
                    {
                        WindowsMxcPathLease.DeleteCreatedPrivateFile(policyPath!, owned);
                    }

                    empty = true;
                }
            }
            catch (Exception cleanup) when (cleanup is IOException or InvalidDataException or Win32Exception or TimeoutException or UnauthorizedAccessException)
            {
                native += "/" + WindowsRunLauncher.NativeCode(cleanup);
            }

            throw new RunNativeException(phase, native, boundaryEmptyVerified: empty, payloadNotStarted: empty && !mayHaveResumed);
        }
        finally
        {
            if (!handedOff)
            {
                io?.Dispose();
                capture?.Dispose();
                executor?.Dispose();
                payload?.Dispose();
                aggregate?.Dispose();
                policy?.Dispose();
                control?.Dispose();
                paths?.Dispose();
                installed?.Dispose();
            }
        }
    }
}
