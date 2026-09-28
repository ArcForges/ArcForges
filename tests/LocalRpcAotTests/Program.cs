// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Platform.Shapes;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using Grpc.AspNetCore.Server;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Transport.NamedPipes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;

internal static partial class Program
{
    private const int MaximumMessageBytes = 4 * 1024 * 1024;

    [SuppressMessage("Usage", "CA1031", Justification = "This executable is a test boundary; report every probe failure and return a failing process exit code.")]
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length > 0 && args[0] == "--worker")
            {
                return await RunWorkerAsync(args[1..]).ConfigureAwait(false);
            }

            if (args.Length > 0 && args[0] == "--rogue")
            {
                return await RunRogueAsync(args[1..]).ConfigureAwait(false);
            }

            if (RuntimeFeature.IsDynamicCodeSupported)
            {
                throw new InvalidOperationException(
                    "Run the published Native AOT executable: dotnet publish tests/LocalRpcAotTests/LocalRpcAotTests.csproj -c Release -r <win-x64|linux-x64|osx-x64|osx-arm64>.");
            }

            await RunProbeAsync().ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception)
        {
            await Console.Error.WriteLineAsync($"PRF.04 failed: {exception}").ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task RunProbeAsync()
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The peer-process probe currently supports Windows named pipes and Linux Unix-domain sockets.");
        }

        var executable = Environment.ProcessPath
            ?? throw new InvalidOperationException("The Native AOT executable path is unavailable.");
        var transport = OperatingSystem.IsWindows() ? "pipe" : "uds";
        var runId = Guid.NewGuid().ToString("N")[..12];
        var directory = Path.Combine(Path.GetTempPath(), "afprf04-" + runId);
        Directory.CreateDirectory(directory);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        try
        {
            var evidence = await RunPairAsync(executable, transport, directory, runId).ConfigureAwait(false);
            Console.WriteLine("PASS: retained owner session completed bidirectional LocalBootstrap, OS-bound peer identity, concurrent/fenced/expiry renewal, cancellation, malformed-input, same-user spoof refusal, reconnect and bounded-message checks.");
            Console.WriteLine($"Evidence: {transport}; owner process {evidence.Owner.ProcessId} / instance {evidence.Owner.InstanceId}; peer restarted {evidence.Peer.ProcessId} / instance {evidence.Peer.InstanceId}; owner session {evidence.OwnerSessionId}.");
        }
        finally
        {
            if (Directory.Exists(directory) && Path.GetFullPath(directory).StartsWith(
                    Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    private static async Task<PairEvidence> RunPairAsync(
        string executable,
        string transport,
        string directory,
        string runId)
    {
        var sharedSecret = RandomNumberGenerator.GetBytes(32);
        var installationA = Guid.NewGuid();
        var installationB = Guid.NewGuid();
        var launchA = RandomNumberGenerator.GetBytes(32);
        var launchB = RandomNumberGenerator.GetBytes(32);
        var addressA = Address(transport, directory, runId, "session", "a");
        var addressB = Address(transport, directory, runId, "session", "b");
        using var processA = StartWorker(executable, "a", transport, addressA, addressB, sharedSecret, installationA, launchA);
        using var processB = StartWorker(executable, "b", transport, addressB, addressA, sharedSecret, installationB, launchB);
        Process? processB2 = null;
        byte[]? reattachSecret = null;
        byte[]? launchB2 = null;

        try
        {
            var readyA = await ReadReadyAsync(processA, installationA, launchA).ConfigureAwait(false);
            var readyB = await ReadReadyAsync(processB, installationB, launchB).ConfigureAwait(false);
            var identityA = readyA.Identity;
            var identityB = readyB.Identity;

            await ExpectPeerAsync(processA, identityB).ConfigureAwait(false);
            await ExpectPeerAsync(processB, identityA).ConfigureAwait(false);
            await RunUnauthorizedChecksAsync(executable, transport, addressB, processB, sharedSecret, identityA, identityB)
                .ConfigureAwait(false);

            await SendCommandAsync(processA, "GO").ConfigureAwait(false);
            await SendCommandAsync(processB, "GO").ConfigureAwait(false);
            var initialA = ParseSession(await ReadLineAsync(processA, TimeSpan.FromSeconds(60)).ConfigureAwait(false));
            var initialB = ParseSession(await ReadLineAsync(processB, TimeSpan.FromSeconds(60)).ConfigureAwait(false));
            if (initialA.ProcessId != identityA.ProcessId || initialA.InstanceId != identityA.InstanceId || initialA.InstallationId != identityA.InstallationId ||
                initialB.ProcessId != identityB.ProcessId || initialB.InstanceId != identityB.InstanceId || initialB.InstallationId != identityB.InstallationId ||
                initialA.OwnerSessionId != readyA.OwnerSessionId)
            {
                throw new InvalidOperationException("The initial owner session did not preserve the parent-provisioned process identities.");
            }

            await SendCommandAsync(processA, "ARM-EXPIRY-RACE|8").ConfigureAwait(false);
            if (await ReadLineAsync(processA, TimeSpan.FromSeconds(5)).ConfigureAwait(false) != "RACE-ARMED|8")
            {
                throw new InvalidOperationException("The server did not arm its controlled lease-expiry race.");
            }

            await SendCommandAsync(processB, "RUN-EXPIRY-RACE|8").ConfigureAwait(false);
            await SendCommandAsync(processA, "WAIT-EXPIRY-RACE").ConfigureAwait(false);
            if (await ReadLineAsync(processA, TimeSpan.FromSeconds(10)).ConfigureAwait(false) != "RACE-REACHED|8" ||
                await ReadLineAsync(processA, TimeSpan.FromSeconds(10)).ConfigureAwait(false) != "RACE-RELEASED")
            {
                throw new InvalidOperationException("The expiry-race barrier did not release after the lease expired.");
            }

            var expiryRace = await ReadLineAsync(processB, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            if (expiryRace != "EXPIRY-RACE|0|8")
            {
                throw new InvalidOperationException("Renewal after the synchronized expiry boundary was not rejected: " + expiryRace);
            }

            await SendCommandAsync(processB, "STOP").ConfigureAwait(false);
            await EnsureExitedAsync(processB).ConfigureAwait(false);
            await SendCommandAsync(processA, "CHECK-OLD-LEASE").ConfigureAwait(false);
            var oldLease = await ReadLineAsync(processA, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            if (oldLease != $"OLD-LEASE|unusable|{readyA.OwnerSessionId}|{identityA.InstanceId}")
            {
                throw new InvalidOperationException("The old peer channel/lease remained usable or the owner session changed: " + oldLease);
            }

            CryptographicOperations.ZeroMemory(sharedSecret);
            reattachSecret = RandomNumberGenerator.GetBytes(32);
            launchB2 = RandomNumberGenerator.GetBytes(32);
            processB2 = StartWorker(executable, "b2", transport, addressB, addressA, reattachSecret!, installationB, launchB2!);
            var readyB2 = await ReadReadyAsync(processB2, installationB, launchB2!).ConfigureAwait(false);
            if (readyB2.Identity.ProcessId == identityB.ProcessId || readyB2.Identity.InstanceId == identityB.InstanceId)
            {
                throw new InvalidOperationException("The restarted peer did not receive a fresh process/instance identity.");
            }

            await ExpectPeerAsync(processB2, identityA).ConfigureAwait(false);
            await SendReattachAsync(processA, readyB2.Identity, reattachSecret!).ConfigureAwait(false);
            await SendCommandAsync(processB2, "GO").ConfigureAwait(false);
            var reattachedA = await ReadLineAsync(processA, TimeSpan.FromSeconds(60)).ConfigureAwait(false);
            var reattachedB = ParseSession(await ReadLineAsync(processB2, TimeSpan.FromSeconds(60)).ConfigureAwait(false));
            if (reattachedA != $"REATTACHED|{readyA.OwnerSessionId}|{identityA.ProcessId}|{identityA.InstanceId}|{readyB2.Identity.InstanceId}" ||
                reattachedB.ProcessId != readyB2.Identity.ProcessId || reattachedB.InstanceId != readyB2.Identity.InstanceId ||
                reattachedB.InstallationId != readyB2.Identity.InstallationId)
            {
                throw new InvalidOperationException("The same owner session did not authenticate the restarted peer identity: " + reattachedA);
            }

            await SendCommandAsync(processA, "STOP").ConfigureAwait(false);
            await SendCommandAsync(processB2, "STOP").ConfigureAwait(false);
            await EnsureExitedAsync(processA).ConfigureAwait(false);
            await EnsureExitedAsync(processB2).ConfigureAwait(false);
            return new PairEvidence(identityA, readyB2.Identity, readyA.OwnerSessionId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(launchA);
            CryptographicOperations.ZeroMemory(launchB);
            if (reattachSecret is not null)
            {
                CryptographicOperations.ZeroMemory(reattachSecret);
            }

            if (launchB2 is not null)
            {
                CryptographicOperations.ZeroMemory(launchB2);
            }

            KillIfRunning(processA);
            KillIfRunning(processB);
            if (processB2 is not null)
            {
                KillIfRunning(processB2);
                processB2.Dispose();
            }
        }
    }

    private static async Task RunUnauthorizedChecksAsync(
        string executable,
        string transport,
        string peerAddress,
        Process server,
        byte[] sharedSecret,
        PeerIdentity spoofedCaller,
        PeerIdentity expectedServer)
    {
        if (await ReadChallengeDispatchCountAsync(server).ConfigureAwait(false) != 0)
        {
            throw new InvalidOperationException("The target worker handled a challenge before the negative-input phase.");
        }

        using var rogue = StartRogue(executable, transport, peerAddress, sharedSecret, spoofedCaller);
        await SendCommandAsync(rogue, $"GO|{spoofedCaller.Serialize()}|{expectedServer.Serialize()}").ConfigureAwait(false);
        if (await ReadLineAsync(rogue, TimeSpan.FromSeconds(30)).ConfigureAwait(false) != "SPOOF|refused")
        {
            throw new InvalidOperationException("A same-user child with the right secret but spoofed process identity was not refused.");
        }

        if (await ReadLineAsync(rogue, TimeSpan.FromSeconds(30)).ConfigureAwait(false) != "MALFORMED|refused")
        {
            throw new InvalidOperationException("The malformed-input refusal stage failed.");
        }

        var dispatches = await ReadChallengeDispatchCountAsync(server).ConfigureAwait(false);
        if (dispatches != 1)
        {
            throw new InvalidOperationException("The spoofed Challenge did not reach the service exactly once.");
        }

        await SendCommandAsync(rogue, "CONTINUE").ConfigureAwait(false);
        if (await ReadLineAsync(rogue, TimeSpan.FromSeconds(30)).ConfigureAwait(false) != "PASS spoofed malformed bounded")
        {
            throw new InvalidOperationException("The same-user spoof/malformed/bounded checks failed.");
        }

        await EnsureExitedAsync(rogue).ConfigureAwait(false);
        if (await ReadChallengeDispatchCountAsync(server).ConfigureAwait(false) != dispatches)
        {
            throw new InvalidOperationException("Malformed or oversized input unexpectedly reached the generated Challenge service method.");
        }
    }

    private static string Address(string transport, string directory, string runId, string round, string side) =>
        transport == "pipe"
            ? $"afprf04-{runId}-{round}-{side}"
            : Path.Combine(directory, $"{round}-{side}.sock");

    private static Process StartWorker(
        string executable,
        string role,
        string transport,
        string ownAddress,
        string peerAddress,
        byte[] secret,
        Guid installationId,
        byte[] launchNonce)
    {
        var process = Start(executable, "--worker", role, transport, ownAddress, peerAddress);
        WriteCredentials(process, secret, launchNonce, GuidBytes(installationId));
        return process;
    }

    private static Process StartRogue(
        string executable,
        string transport,
        string peerAddress,
        byte[] secret,
        PeerIdentity spoofedCaller)
    {
        var process = Start(executable, "--rogue", transport, peerAddress);
        WriteCredentials(process, secret, Convert.FromHexString(spoofedCaller.LaunchNonce), Convert.FromHexString(spoofedCaller.InstallationId));
        return process;
    }

    private static Process Start(string executable, params string[] arguments)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = false,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        var process = Process.Start(start) ?? throw new InvalidOperationException("Failed to start a probe process.");
        return process;
    }

    private static async Task<WorkerReady> ReadReadyAsync(Process process, Guid installationId, byte[] launchNonce)
    {
        var line = await ReadLineAsync(process, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
        var parts = line.Split('|');
        if (parts.Length != 4 || parts[0] != "READY" || !int.TryParse(parts[1], out var processId) ||
            !Guid.TryParseExact(parts[3], "N", out var ownerSession))
        {
            throw new InvalidOperationException("Invalid process-ready record: " + line);
        }

        if (processId != process.Id)
        {
            throw new InvalidOperationException("The worker-reported PID did not match the PID assigned by the parent process API.");
        }

        return new WorkerReady(
            new PeerIdentity(processId, parts[2], Convert.ToHexString(GuidBytes(installationId)), Convert.ToHexString(launchNonce)),
            ownerSession.ToString("N"));
    }

    private static async Task ExpectPeerAsync(Process process, PeerIdentity identity)
    {
        await SendCommandAsync(process, "EXPECT|" + identity.Serialize()).ConfigureAwait(false);
        var response = await ReadLineAsync(process, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        if (response != "EXPECTED|" + identity.InstanceId)
        {
            throw new InvalidOperationException("The worker did not install the parent-provisioned expected peer identity: " + response);
        }
    }

    private static async Task SendReattachAsync(Process process, PeerIdentity identity, byte[] secret)
    {
        await SendCommandAsync(process, $"REATTACH|{identity.Serialize()}|{Convert.ToBase64String(secret)}").ConfigureAwait(false);
    }

    private static SessionEvidence ParseSession(string line)
    {
        var parts = line.Split('|');
        if (parts.Length != 5 || parts[0] != "SESSION" || !int.TryParse(parts[2], out var processId))
        {
            throw new InvalidOperationException("Invalid worker session record: " + line);
        }

        return new SessionEvidence(parts[1], processId, parts[3], parts[4]);
    }

    private static async Task<string> ReadLineAsync(Process process, TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        var read = await process.StandardOutput.ReadLineAsync(cancellation.Token).ConfigureAwait(false);
        if (read is null)
        {
            throw new InvalidOperationException($"Probe process {process.Id} exited before producing its result.");
        }

        return read;
    }

    private static async Task<int> ReadChallengeDispatchCountAsync(Process worker)
    {
        await SendCommandAsync(worker, "COUNT").ConfigureAwait(false);
        var line = await ReadLineAsync(worker, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        var parts = line.Split('|');
        if (parts.Length != 2 || parts[0] != "CHALLENGE-DISPATCHES" || !int.TryParse(parts[1], out var count))
        {
            throw new InvalidOperationException("The worker returned an invalid private dispatch-count record: " + line);
        }

        return count;
    }

    private static async Task SendCommandAsync(Process process, string command)
    {
        await process.StandardInput.WriteLineAsync(command).ConfigureAwait(false);
        await process.StandardInput.FlushAsync().ConfigureAwait(false);
    }

    private static void WriteCredentials(Process process, byte[] secret, byte[] launchNonce, byte[] installationId)
    {
        if (secret.Length != 32 || launchNonce.Length != 32 || installationId.Length != 16)
        {
            throw new ArgumentException("The private process bootstrap credential has an invalid fixed width.");
        }

        var credentials = new byte[80];
        secret.CopyTo(credentials, 0);
        launchNonce.CopyTo(credentials, 32);
        installationId.CopyTo(credentials, 64);
        process.StandardInput.BaseStream.Write(credentials);
        process.StandardInput.BaseStream.Flush();
        CryptographicOperations.ZeroMemory(credentials);
    }

    private static async Task EnsureExitedAsync(Process process)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await process.WaitForExitAsync(cancellation.Token).ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Probe process {process.Id} exited {process.ExitCode}.");
        }
    }

    private static void KillIfRunning(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
            }
        }
        catch (InvalidOperationException)
        {
            // The child exited between the state check and termination.
        }
    }

    [SuppressMessage("Reliability", "CA2000", Justification = "The long-lived owner client session is disposed on STOP and in the worker's finally block; reattach replaces it only after the old session has been disposed.")]
    private static async Task<int> RunWorkerAsync(string[] args)
    {
        if (args.Length != 4)
        {
            throw new ArgumentException("Worker requires role, transport, endpoint address and peer address.");
        }

        var role = args[0];
        if (role is not ("a" or "b" or "b2"))
        {
            throw new ArgumentException("Worker role was not recognized.");
        }
        var transport = args[1];
        var ownAddress = args[2];
        var peerAddress = args[3];
        var control = Console.OpenStandardInput();
        var credentials = new byte[80];
        await control.ReadExactlyAsync(credentials).ConfigureAwait(false);
        var secret = credentials[..32];
        var launchNonce = credentials[32..64];
        var installationId = new Guid(credentials.AsSpan(64, 16), bigEndian: true);
        CryptographicOperations.ZeroMemory(credentials);
        using var controlReader = new StreamReader(control, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 256, leaveOpen: true);
        var instance = Guid.NewGuid();
        var ownerSessionId = Guid.NewGuid().ToString("N");
        var ownManifest = CreateManifest(transport, ownAddress, instance, installationId);
        var state = new BootstrapState(secret, ownManifest, instance, launchNonce, ownerSessionId);
        var app = CreateServer(transport, ownAddress, state);
        ClientSession? ownerClientSession = null;
        await using (app.ConfigureAwait(false))
        {
            await app.StartAsync().ConfigureAwait(false);
            Console.WriteLine($"READY|{Environment.ProcessId}|{Convert.ToHexString(GuidBytes(instance))}|{ownerSessionId}");
            try
            {
                while (true)
                {
                    var command = await controlReader.ReadLineAsync().ConfigureAwait(false)
                        ?? throw new InvalidOperationException("Parent closed the private probe control stream before STOP.");
                    if (command == "COUNT")
                    {
                        await Console.Out.WriteLineAsync($"CHALLENGE-DISPATCHES|{state.ChallengeDispatchCount}").ConfigureAwait(false);
                        continue;
                    }

                    var parts = command.Split('|');
                    if (parts[0] == "EXPECT" && parts.Length == 5)
                    {
                        var expectedPeer = PeerIdentity.Parse(parts, 1);
                        state.SetExpectedPeer(expectedPeer);
                        await Console.Out.WriteLineAsync("EXPECTED|" + expectedPeer.InstanceId).ConfigureAwait(false);
                        continue;
                    }

                    if (command == "GO")
                    {
                        ownerClientSession = await RunClientChecksAsync(state, transport, peerAddress, runCancellationCheck: role != "b2").ConfigureAwait(false);
                        await WaitForAuthenticatedPeerAsync(state).ConfigureAwait(false);
                        await Console.Out.WriteLineAsync(FormatSession(state)).ConfigureAwait(false);
                        continue;
                    }

                    if (parts[0] == "ARM-EXPIRY-RACE" && parts.Length == 2 && int.TryParse(parts[1], out var expectedCalls))
                    {
                        state.ArmExpiryRace(expectedCalls, TimeSpan.FromSeconds(2));
                        await Console.Out.WriteLineAsync($"RACE-ARMED|{expectedCalls}").ConfigureAwait(false);
                        continue;
                    }

                    if (command == "WAIT-EXPIRY-RACE")
                    {
                        var race = state.ExpiryRace ?? throw new InvalidOperationException("No lease expiry race was armed.");
                        await race.Arrived.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                        await Console.Out.WriteLineAsync($"RACE-REACHED|{race.ExpectedCalls}").ConfigureAwait(false);
                        var wait = race.ExpiresAt - DateTimeOffset.UtcNow;
                        if (wait > TimeSpan.Zero)
                        {
                            await Task.Delay(wait + TimeSpan.FromMilliseconds(20)).ConfigureAwait(false);
                        }

                        race.Release.TrySetResult();
                        await Console.Out.WriteLineAsync("RACE-RELEASED").ConfigureAwait(false);
                        continue;
                    }

                    if (parts[0] == "RUN-EXPIRY-RACE" && parts.Length == 2 && int.TryParse(parts[1], out var renewCalls))
                    {
                        if (ownerClientSession is null)
                        {
                            throw new InvalidOperationException("Cannot run a lease race before the owner client session is authenticated.");
                        }

                        var result = await RunRenewRaceAsync(ownerClientSession, renewCalls, expectSuccess: false).ConfigureAwait(false);
                        await Console.Out.WriteLineAsync($"EXPIRY-RACE|{result.Successes}|{result.Refusals}").ConfigureAwait(false);
                        continue;
                    }

                    if (command == "CHECK-OLD-LEASE")
                    {
                        if (ownerClientSession is null)
                        {
                            throw new InvalidOperationException("The original owner client session is unavailable.");
                        }

                        var old = ownerClientSession;
                        ownerClientSession = null;
                        var unavailable = await CheckOldChannelAsync(old).ConfigureAwait(false);
                        await state.WaitForNoActiveLeasesAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                        await Console.Out.WriteLineAsync($"OLD-LEASE|{(unavailable ? "unusable" : "usable")}|{state.OwnerSessionId}|{Convert.ToHexString(GuidBytes(state.InstanceId))}").ConfigureAwait(false);
                        continue;
                    }

                    if (parts[0] == "REATTACH" && parts.Length == 6)
                    {
                        var expectedPeer = PeerIdentity.Parse(parts, 1);
                        var newSecret = Convert.FromBase64String(parts[5]);
                        if (newSecret.Length != 32)
                        {
                            throw new InvalidOperationException("Re-attach secret has an invalid width.");
                        }

                        state.BeginPeerEpoch(newSecret, expectedPeer);
                        CryptographicOperations.ZeroMemory(newSecret);
                        ownerClientSession = await RunClientChecksAsync(state, transport, peerAddress, runCancellationCheck: false).ConfigureAwait(false);
                        await WaitForAuthenticatedPeerAsync(state).ConfigureAwait(false);
                        await Console.Out.WriteLineAsync($"REATTACHED|{state.OwnerSessionId}|{Environment.ProcessId}|{Convert.ToHexString(GuidBytes(state.InstanceId))}|{expectedPeer.InstanceId}").ConfigureAwait(false);
                        continue;
                    }

                    if (command == "STOP")
                    {
                        if (ownerClientSession is not null)
                        {
                            await ownerClientSession.DisposeAsync().ConfigureAwait(false);
                            ownerClientSession = null;
                        }

                        await app.StopAsync().ConfigureAwait(false);
                        return 0;
                    }

                    throw new InvalidOperationException("Invalid private probe control command.");
                }
            }
            finally
            {
                if (ownerClientSession is not null)
                {
                    await ownerClientSession.DisposeAsync().ConfigureAwait(false);
                }

                state.ClearSecrets();
            }
        }
    }

    private static string FormatSession(BootstrapState state) =>
        $"SESSION|{state.OwnerSessionId}|{Environment.ProcessId}|{Convert.ToHexString(GuidBytes(state.InstanceId))}|{Convert.ToHexString(GuidBytes(new Guid(state.Manifest.InstallationId.Value.Span, bigEndian: true)))}";

    private static async Task WaitForAuthenticatedPeerAsync(BootstrapState state)
    {
        await state.BothDirectionsAuthenticated.Task.WaitAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
        await state.PeerRenewalObserved.Task.WaitAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
    }

    [SuppressMessage("Reliability", "CA2000", Justification = "A successful channel is transferred into the returned ClientSession; all failed handshakes dispose it before rethrowing.")]
    private static async Task<ClientSession> RunClientChecksAsync(
        BootstrapState state,
        string transport,
        string peerAddress,
        bool runCancellationCheck)
    {
        var expectedPeer = state.ExpectedPeer ?? throw new InvalidOperationException("The parent did not provision an expected peer identity.");
        if (runCancellationCheck)
        {
            using var cancelChannel = CreateChannel(transport, peerAddress, expectedPeer.ProcessId);
            var cancelService = new LocalBootstrapService.LocalBootstrapServiceClient(cancelChannel.Channel);
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
            var request = NewChallengeRequest(state.Manifest, RandomNumberGenerator.GetBytes(32));
            request.Challenge = ByteString.CopyFrom([0xEE, .. new byte[31]]);
            try
            {
                _ = await cancelService.ChallengeAsync(request, headers: IdentityHeaders(state.LaunchNonce), deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: cancellation.Token)
                    .ResponseAsync.ConfigureAwait(false);
                throw new InvalidOperationException("A canceled LocalBootstrap call unexpectedly completed.");
            }
            catch (RpcException exception) when (exception.StatusCode == StatusCode.Cancelled)
            {
                await state.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            }
        }

        var channel = CreateChannel(transport, peerAddress, expectedPeer.ProcessId);
        try
        {
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.Channel);
            var clientChallenge = RandomNumberGenerator.GetBytes(32);
            var challengeCall = client.ChallengeAsync(
                NewChallengeRequest(state.Manifest, clientChallenge),
                headers: IdentityHeaders(state.LaunchNonce),
                deadline: DateTime.UtcNow.AddSeconds(5));
            var challengeResponse = await challengeCall.ResponseAsync.ConfigureAwait(false);
            var challengeHeaders = await challengeCall.ResponseHeadersAsync.ConfigureAwait(false);
            if (challengeResponse.OutcomeCase != LocalBootstrapServiceChallengeResponse.OutcomeOneofCase.Value)
            {
                throw new InvalidOperationException("The peer did not issue a valid LocalBootstrap challenge.");
            }

            var server = challengeResponse.Value.Server;
            if (server.ProcessId != (ulong)expectedPeer.ProcessId ||
                !server.InstanceId.Value.Span.SequenceEqual(Convert.FromHexString(expectedPeer.InstanceId)) ||
                !server.Endpoint.InstanceId.Value.Span.SequenceEqual(Convert.FromHexString(expectedPeer.InstanceId)) ||
                !server.InstallationId.Value.Span.SequenceEqual(Convert.FromHexString(expectedPeer.InstallationId)) ||
                server.Endpoint.Transport != transport ||
                server.Endpoint.Address != peerAddress ||
                server.AppId != "org.arcforges.prf04.probe" ||
                server.SchemaVersion != "1" ||
                server.ContractSetHash != state.Manifest.ContractSetHash ||
                challengeHeaders.GetValue("x-af-launch") != expectedPeer.LaunchNonce ||
                !channel.PeerProcessIds.All(processId => processId == expectedPeer.ProcessId) ||
                challengeResponse.Value.ServerChallenge.Length != 32 ||
                !IsFutureBounded(challengeResponse.Value.ExpiresAt, TimeSpan.FromSeconds(5)))
            {
                throw new InvalidOperationException("The authenticated peer manifest or bounded challenge did not match the parent-verified process identity.");
            }

            var proof = BootstrapProof(
                state.Secret,
                challengeResponse.Value.ChallengeId.Value.Span,
                clientChallenge,
                challengeResponse.Value.ServerChallenge.Span,
                state.Manifest.InstanceId.Value.Span,
                server.InstanceId.Value.Span);
            CryptographicOperations.ZeroMemory(clientChallenge);
            var confirmCall = client.ConfirmAsync(
                new LocalBootstrapServiceConfirmRequest
                {
                    Meta = NewMeta(),
                    ChallengeId = challengeResponse.Value.ChallengeId,
                    Proof = ByteString.CopyFrom(proof),
                },
                headers: IdentityHeaders(state.LaunchNonce),
                deadline: DateTime.UtcNow.AddSeconds(5));
            var confirmResponse = await confirmCall.ResponseAsync.ConfigureAwait(false);
            var confirmHeaders = await confirmCall.ResponseHeadersAsync.ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(proof);
            if (confirmResponse.OutcomeCase != LocalBootstrapServiceConfirmResponse.OutcomeOneofCase.Value ||
                confirmResponse.Value.PeerNonce.Length != 32)
            {
                throw new InvalidOperationException("The peer refused the one-use LocalBootstrap confirmation.");
            }

            state.MarkClientAuthenticated();
            var session = new ClientSession(channel, client, state.LaunchNonce, expectedPeer, confirmResponse.Value.PeerNonce.ToByteArray(), confirmHeaders);
            var renewal = await RunRenewRaceAsync(session, 8, expectSuccess: true).ConfigureAwait(false);
            if (renewal.Successes != 1 || renewal.Refusals != 7)
            {
                await session.DisposeAsync().ConfigureAwait(false);
                throw new InvalidOperationException($"Concurrent same-lease renewals did not linearize behind one current epoch/fence: {renewal.Successes} succeeded, {renewal.Refusals} refused.");
            }

            return session;
        }
        catch
        {
            await channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task<RenewRaceResult> RunRenewRaceAsync(ClientSession session, int requestCount, bool expectSuccess)
    {
        var calls = Enumerable.Range(0, requestCount).Select(_ => SendRenewAsync(session)).ToArray();
        var results = await Task.WhenAll(calls).ConfigureAwait(false);
        var successes = results.Count(static result => result.Success);
        var refusals = results.Length - successes;
        if (expectSuccess)
        {
            if (successes != 1 || refusals != requestCount - 1)
            {
                return new RenewRaceResult(successes, refusals);
            }
        }
        else if (successes != 0 || refusals != requestCount)
        {
            return new RenewRaceResult(successes, refusals);
        }

        foreach (var result in results)
        {
            if (result.Epoch >= session.Epoch)
            {
                session.UpdateLease(result.Epoch, result.Fence);
            }
        }

        return new RenewRaceResult(successes, refusals);
    }

    private static async Task<RenewResult> SendRenewAsync(ClientSession session)
    {
        var lease = session.SnapshotLease();
        var headers = IdentityHeaders(session.LaunchNonce);
        headers.Add("x-af-lease-id", lease.LeaseId);
        headers.Add("x-af-lease-epoch", lease.Epoch.ToString(System.Globalization.CultureInfo.InvariantCulture));
        headers.Add("x-af-lease-fence", lease.Fence);
        var call = session.Client.RenewAsync(
            new LocalBootstrapServiceRenewRequest { Meta = NewMeta() },
            headers: headers,
            deadline: DateTime.UtcNow.AddSeconds(10));
        var response = await call.ResponseAsync.ConfigureAwait(false);
        var responseHeaders = await call.ResponseHeadersAsync.ConfigureAwait(false);
        var epochText = responseHeaders.GetValue("x-af-lease-epoch");
        var fence = responseHeaders.GetValue("x-af-lease-fence");
        if (!long.TryParse(epochText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var epoch) ||
            string.IsNullOrEmpty(fence))
        {
            throw new InvalidOperationException("Renew returned no current lease epoch/fence metadata.");
        }

        if (response.OutcomeCase == LocalBootstrapServiceRenewResponse.OutcomeOneofCase.Value)
        {
            if (!IsFutureBounded(response.Value.ExpiresAt, TimeSpan.FromSeconds(30)))
            {
                throw new InvalidOperationException("The renewed lease exceeded its 30-second bound or was already expired.");
            }

            return new RenewResult(true, epoch, fence);
        }

        if (response.OutcomeCase != LocalBootstrapServiceRenewResponse.OutcomeOneofCase.Error ||
            response.Error.Category != ErrorCategory.Authentication)
        {
            throw new InvalidOperationException("A stale/expired renewal did not return a bounded authentication refusal.");
        }

        return new RenewResult(false, epoch, fence);
    }

    private static async Task<bool> CheckOldChannelAsync(ClientSession session)
    {
        try
        {
            _ = await SendRenewAsync(session).WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            await session.DisposeAsync().ConfigureAwait(false);
            return false;
        }
        catch (Exception exception) when (exception is RpcException or TimeoutException or OperationCanceledException)
        {
            await session.DisposeAsync().ConfigureAwait(false);
            return true;
        }
    }

    private static Metadata IdentityHeaders(byte[] launchNonce) =>
        new() { { "x-af-launch", Convert.ToHexString(launchNonce) } };

    private static async Task<int> RunRogueAsync(string[] args)
    {
        if (args.Length != 2)
        {
            throw new ArgumentException("Rogue requires transport and peer address.");
        }

        var transport = args[0];
        var peerAddress = args[1];
        var control = Console.OpenStandardInput();
        var credentials = new byte[80];
        await control.ReadExactlyAsync(credentials).ConfigureAwait(false);
        var launchNonce = credentials[32..64];
        CryptographicOperations.ZeroMemory(credentials);
        using var controlReader = new StreamReader(control, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 256, leaveOpen: true);
        var command = await controlReader.ReadLineAsync().ConfigureAwait(false);
        var parts = command?.Split('|') ?? [];
        if (parts.Length != 9 || parts[0] != "GO")
        {
            throw new InvalidOperationException("Parent closed the private rogue control stream before GO.");
        }

        var spoofedCaller = PeerIdentity.Parse(parts, 1);
        var expectedServer = PeerIdentity.Parse(parts, 5);
        if (Convert.ToHexString(launchNonce) != spoofedCaller.LaunchNonce)
        {
            throw new InvalidOperationException("The parent-provisioned launch binding did not match the spoof attempt.");
        }

        using var channel = CreateChannel(transport, peerAddress, expectedServer.ProcessId);
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.Channel);
        var clientChallenge = RandomNumberGenerator.GetBytes(32);
        var challengeCall = client.ChallengeAsync(
            NewChallengeRequest(CreateManifest(
                transport,
                "spoofed",
                Guid.ParseExact(spoofedCaller.InstanceId, "N"),
                Guid.ParseExact(spoofedCaller.InstallationId, "N"),
                (ulong)spoofedCaller.ProcessId), clientChallenge),
            headers: IdentityHeaders(launchNonce),
            deadline: DateTime.UtcNow.AddSeconds(5));
        var challengeResponse = await challengeCall.ResponseAsync.ConfigureAwait(false);
        if (challengeResponse.OutcomeCase != LocalBootstrapServiceChallengeResponse.OutcomeOneofCase.Error ||
            challengeResponse.Error.Category != ErrorCategory.Authentication)
        {
            throw new InvalidOperationException("The server accepted a same-user child that spoofed the expected PID/instance/launch tuple.");
        }

        CryptographicOperations.ZeroMemory(clientChallenge);
        await Console.Out.WriteLineAsync("SPOOF|refused").ConfigureAwait(false);

        await VerifyMalformedInputAsync(channel.Channel).ConfigureAwait(false);
        await Console.Out.WriteLineAsync("MALFORMED|refused").ConfigureAwait(false);
        if (await controlReader.ReadLineAsync().ConfigureAwait(false) != "CONTINUE")
        {
            throw new InvalidOperationException("Parent did not continue the malformed-input recovery check.");
        }

        await VerifyBoundedInputAsync(client).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(launchNonce);
        await Console.Out.WriteLineAsync("PASS spoofed malformed bounded").ConfigureAwait(false);
        return 0;
    }

    private static async Task VerifyMalformedInputAsync(GrpcChannel channel)
    {
        var invalid = new byte[] { 0xFF };
        var method = new Method<byte[], byte[]>(
            MethodType.Unary,
            "arcforges.local.platform.v1.LocalBootstrapService",
            "Challenge",
            Marshallers.Create(static payload => payload, static payload => payload),
            Marshallers.Create(static payload => payload, static payload => payload));
        using var call = channel.CreateCallInvoker().AsyncUnaryCall(
            method,
            host: null,
            options: new CallOptions(deadline: DateTime.UtcNow.AddSeconds(5)),
            request: invalid);
        try
        {
            _ = await call.ResponseAsync.ConfigureAwait(false);
            throw new InvalidOperationException("Malformed protobuf input was accepted.");
        }
        catch (RpcException exception)
        {
            VerifySanitizedMalformedRefusal(exception);
        }
    }

    private static void VerifySanitizedMalformedRefusal(RpcException exception)
    {
        var detail = exception.Status.Detail;
        if (exception.StatusCode == StatusCode.OK || !IsSanitizedDiagnostic(detail) || exception.Trailers.Count > 8)
        {
            throw new InvalidOperationException("Malformed protobuf refusal was successful or returned an unbounded/unsafe status detail.");
        }

        var trailerBytes = 0;
        foreach (var trailer in exception.Trailers)
        {
            if (!IsSanitizedDiagnostic(trailer.Key) || trailer.IsBinary)
            {
                throw new InvalidOperationException("Malformed protobuf refusal returned an unsafe or opaque binary trailer.");
            }

            trailerBytes += Encoding.UTF8.GetByteCount(trailer.Key) + Encoding.UTF8.GetByteCount(trailer.Value);
            if (!IsSanitizedDiagnostic(trailer.Value))
            {
                throw new InvalidOperationException("Malformed protobuf refusal trailer leaked sensitive or unbounded detail.");
            }
        }

        if (Encoding.UTF8.GetByteCount(detail) + trailerBytes > 512)
        {
            throw new InvalidOperationException("Malformed protobuf refusal status metadata exceeded its 512-byte bound.");
        }
    }

    private static bool IsSanitizedDiagnostic(string value) =>
        value.Length <= 160 &&
        value.All(character => character is >= ' ' and <= '~') &&
        !value.Contains('/') &&
        !value.Contains('\\') &&
        value.IndexOf("stack", StringComparison.OrdinalIgnoreCase) < 0 &&
        value.IndexOf("path", StringComparison.OrdinalIgnoreCase) < 0 &&
        value.IndexOf("secret", StringComparison.OrdinalIgnoreCase) < 0;

    private static async Task VerifyNormalChallengeAsync(LocalBootstrapService.LocalBootstrapServiceClient client, string transport)
    {
        var challenge = RandomNumberGenerator.GetBytes(32);
        try
        {
            var response = await client.ChallengeAsync(
                NewChallengeRequest(CreateManifest(transport, "post-malformed", Guid.NewGuid()), challenge),
                deadline: DateTime.UtcNow.AddSeconds(5)).ResponseAsync.ConfigureAwait(false);
            if (response.OutcomeCase != LocalBootstrapServiceChallengeResponse.OutcomeOneofCase.Value ||
                response.Value.ServerChallenge.Length != 32)
            {
                throw new InvalidOperationException("A normal generated LocalBootstrap call did not succeed after malformed input.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
        }
    }

    private static async Task VerifyBoundedInputAsync(LocalBootstrapService.LocalBootstrapServiceClient client)
    {
        var request = NewChallengeRequest(
            CreateManifest(OperatingSystem.IsWindows() ? "pipe" : "uds", "bounded-input", Guid.NewGuid()),
            new byte[MaximumMessageBytes + 1]);
        try
        {
            _ = await client.ChallengeAsync(request, deadline: DateTime.UtcNow.AddSeconds(10)).ResponseAsync.ConfigureAwait(false);
            throw new InvalidOperationException("The server accepted a request beyond the 4 MiB gRPC message bound.");
        }
        catch (RpcException exception) when (exception.StatusCode == StatusCode.ResourceExhausted)
        {
            // The server-side gRPC receive bound rejected this before service dispatch.
        }
    }

    private static WebApplication CreateServer(string transport, string address, BootstrapState state)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        if (OperatingSystem.IsWindows())
        {
            builder.WebHost.UseNamedPipes(options => options.CurrentUserOnly = true);
        }

        builder.WebHost.ConfigureKestrel(options =>
        {
            if (transport == "pipe")
            {
                options.ListenNamedPipe(address, listen => listen.Protocols = HttpProtocols.Http2);
            }
            else
            {
                options.ListenUnixSocket(address, listen => listen.Protocols = HttpProtocols.Http2);
            }
        });
        builder.Services.AddSingleton(state);
        builder.Services.AddGrpc(options =>
        {
            options.MaxReceiveMessageSize = MaximumMessageBytes;
            options.MaxSendMessageSize = MaximumMessageBytes;
        });
        builder.Services.AddSingleton(new LocalBootstrapProbeService(state));
        var app = builder.Build();
        app.MapGrpcService<LocalBootstrapProbeService>();
        return app;
    }

    private static ProbeChannel CreateChannel(string transport, string address, int expectedPeerPid)
    {
        var peerProcessIds = new ConcurrentQueue<int>();
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            EnableMultipleHttp2Connections = true,
            ConnectCallback = async (_, cancellationToken) =>
            {
                if (transport == "pipe")
                {
                    var pipe = new System.IO.Pipes.NamedPipeClientStream(
                        serverName: ".",
                        pipeName: address,
                        direction: System.IO.Pipes.PipeDirection.InOut,
                        options: System.IO.Pipes.PipeOptions.Asynchronous,
                        impersonationLevel: System.Security.Principal.TokenImpersonationLevel.Anonymous);
                    try
                    {
                        await pipe.ConnectAsync(cancellationToken).ConfigureAwait(false);
                        var peerPid = GetNamedPipeServerProcessId(pipe.SafePipeHandle);
                        if (peerPid != expectedPeerPid)
                        {
                            throw new UnauthorizedAccessException("The named-pipe server PID did not match the parent-provisioned peer.");
                        }

                        peerProcessIds.Enqueue(peerPid);
                        return pipe;
                    }
                    catch
                    {
                        await pipe.DisposeAsync().ConfigureAwait(false);
                        throw;
                    }
                }

                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(new UnixDomainSocketEndPoint(address), cancellationToken).ConfigureAwait(false);
                    var peerPid = GetUnixPeerProcessId(socket);
                    if (peerPid != expectedPeerPid)
                    {
                        throw new UnauthorizedAccessException("The Unix-domain socket peer PID did not match the parent-provisioned peer.");
                    }

                    peerProcessIds.Enqueue(peerPid);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };

        var channel = GrpcChannel.ForAddress("http://arcforges.invalid", new GrpcChannelOptions
        {
            HttpHandler = handler,
            MaxSendMessageSize = MaximumMessageBytes + 64 * 1024,
            MaxReceiveMessageSize = MaximumMessageBytes,
        });
        return new ProbeChannel(channel, peerProcessIds);
    }

    private static LocalBootstrapServiceChallengeRequest NewChallengeRequest(EndpointManifest caller, byte[] challenge) => new()
    {
        Meta = NewMeta(),
        InstanceId = caller.InstanceId,
        Challenge = ByteString.CopyFrom(challenge),
        Caller = caller,
    };

    private static RequestMeta NewMeta() => new() { CorrelationId = NewId(), CommandId = NewId() };

    private static bool IsFutureBounded(Instant expiry, TimeSpan maximum)
    {
        if (expiry.Nanos >= 1_000_000_000)
        {
            return false;
        }

        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiry.UnixSeconds)
            .AddTicks(expiry.Nanos / 100);
        var now = DateTimeOffset.UtcNow;
        return expiresAt > now && expiresAt <= now.Add(maximum);
    }

    private static EndpointManifest CreateManifest(string transport, string address, Guid instance) =>
        CreateManifest(transport, address, instance, Guid.NewGuid(), (ulong)Environment.ProcessId);

    private static EndpointManifest CreateManifest(string transport, string address, Guid instance, Guid installationId, ulong? processId = null)
    {
        using var process = Process.GetCurrentProcess();
        var descriptor = PlatformReflection.Descriptor.ToProto().ToByteArray();
        return new EndpointManifest
        {
            SchemaVersion = "1",
            AppId = "org.arcforges.prf04.probe",
            InstallationId = ToId(installationId),
            InstanceId = ToId(instance),
            ProcessId = processId ?? (ulong)Environment.ProcessId,
            ProcessStartedAt = ToInstant(process.StartTime.ToUniversalTime()),
            Endpoint = new LocalEndpoint
            {
                Transport = transport,
                Address = address,
                InstanceId = ToId(instance),
            },
            BuildHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Environment.ProcessPath ?? "aot-probe"))).ToLowerInvariant(),
            ContractSetHash = Convert.ToHexString(SHA256.HashData(descriptor)).ToLowerInvariant(),
            ContractMajors = { 1 },
        };
    }

    internal static bool MatchesExpectedPeer(BootstrapState state, ServerCallContext context, EndpointManifest caller)
    {
        var expected = state.ExpectedPeer;
        if (expected is null || !ContractShapeValidation.IsValid(caller))
        {
            return false;
        }

        try
        {
            return MatchesExpectedTransportPeer(state, context) &&
                caller.ProcessId == (ulong)expected.ProcessId &&
                caller.InstanceId.Value.Span.SequenceEqual(Convert.FromHexString(expected.InstanceId)) &&
                caller.Endpoint.InstanceId.Value.Span.SequenceEqual(Convert.FromHexString(expected.InstanceId)) &&
                caller.InstallationId.Value.Span.SequenceEqual(Convert.FromHexString(expected.InstallationId));
        }
        catch (Exception exception) when (exception is InvalidOperationException or PlatformNotSupportedException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    internal static bool MatchesExpectedTransportPeer(BootstrapState state, ServerCallContext context)
    {
        var expected = state.ExpectedPeer;
        if (expected is null)
        {
            return false;
        }

        try
        {
            return GetServerObservedPeerProcessId(context.GetHttpContext()) == expected.ProcessId &&
                context.RequestHeaders.GetValue("x-af-launch") == expected.LaunchNonce;
        }
        catch (Exception exception) when (exception is InvalidOperationException or PlatformNotSupportedException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static int GetServerObservedPeerProcessId(HttpContext context)
    {
        var pipe = context.Features.Get<IConnectionNamedPipeFeature>()?.NamedPipe;
        if (pipe is not null)
        {
            return GetNamedPipeClientProcessId(pipe.SafePipeHandle);
        }

        var socket = context.Features.Get<IConnectionSocketFeature>()?.Socket;
        if (socket is not null)
        {
            return GetUnixPeerProcessId(socket);
        }

        throw new InvalidOperationException("The server connection did not expose a named-pipe or Unix-socket peer handle.");
    }

    private static int GetNamedPipeClientProcessId(SafePipeHandle pipe)
    {
        if (!OperatingSystem.IsWindows() || !NativeMethods.GetNamedPipeClientProcessId(pipe, out var processId))
        {
            throw new IOException("The accepted named-pipe client process ID could not be observed.", new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        return checked((int)processId);
    }

    private static int GetNamedPipeServerProcessId(SafePipeHandle pipe)
    {
        if (!OperatingSystem.IsWindows() || !NativeMethods.GetNamedPipeServerProcessId(pipe, out var processId))
        {
            throw new IOException("The connected named-pipe server process ID could not be observed.", new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        return checked((int)processId);
    }

    private static int GetUnixPeerProcessId(Socket socket)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("Unix-domain peer PID binding is currently implemented for Linux only.");
        }

        var credentials = default(LinuxPeerCredentials);
        uint length = (uint)Marshal.SizeOf<LinuxPeerCredentials>();
        if (NativeMethods.GetSocketOption(socket.SafeHandle, level: 1, option: 17, out credentials, ref length) != 0 ||
            length < Marshal.SizeOf<LinuxPeerCredentials>() || credentials.ProcessId <= 0)
        {
            throw new IOException("The Unix-domain socket peer process ID could not be observed.", new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        return credentials.ProcessId;
    }

    internal static Metadata LaunchResponseHeaders(byte[] launchNonce) =>
        new() { { "x-af-launch", Convert.ToHexString(launchNonce) } };

    internal static Metadata LeaseResponseHeaders(long epoch, string fence) =>
        new()
        {
            { "x-af-lease-epoch", epoch.ToString(System.Globalization.CultureInfo.InvariantCulture) },
            { "x-af-lease-fence", fence },
        };

    internal static byte[] BootstrapProof(
        byte[] secret,
        ReadOnlySpan<byte> challengeId,
        ReadOnlySpan<byte> clientChallenge,
        ReadOnlySpan<byte> serverChallenge,
        ReadOnlySpan<byte> clientInstance,
        ReadOnlySpan<byte> serverInstance)
    {
        var domain = Encoding.UTF8.GetBytes("arcforges.local.bootstrap.v1");
        var transcript = new byte[domain.Length + 16 + 32 + 32 + 16 + 16];
        var offset = 0;
        domain.CopyTo(transcript, offset);
        offset += domain.Length;
        challengeId.CopyTo(transcript.AsSpan(offset, 16));
        offset += 16;
        clientChallenge.CopyTo(transcript.AsSpan(offset, 32));
        offset += 32;
        serverChallenge.CopyTo(transcript.AsSpan(offset, 32));
        offset += 32;
        clientInstance.CopyTo(transcript.AsSpan(offset, 16));
        offset += 16;
        serverInstance.CopyTo(transcript.AsSpan(offset, 16));
        var proof = HMACSHA256.HashData(secret, transcript);
        CryptographicOperations.ZeroMemory(transcript);
        CryptographicOperations.ZeroMemory(domain);
        return proof;
    }

    private static Id NewId() => ToId(Guid.NewGuid());

    internal static Id ToId(Guid value) => new() { Value = ByteString.CopyFrom(GuidBytes(value)) };

    internal static byte[] GuidBytes(Guid value)
    {
        var bytes = new byte[16];
        if (!value.TryWriteBytes(bytes, bigEndian: true, out var written) || written != 16)
        {
            throw new InvalidOperationException("Could not encode the UUID transcript in RFC byte order.");
        }

        return bytes;
    }

    internal static Instant ToInstant(DateTime value) => new()
    {
        UnixSeconds = new DateTimeOffset(value, TimeSpan.Zero).ToUnixTimeSeconds(),
        Nanos = (uint)(value.Ticks % TimeSpan.TicksPerSecond * 100),
    };

    internal sealed record PeerIdentity(int ProcessId, string InstanceId, string InstallationId, string LaunchNonce)
    {
        public string Serialize() => $"{ProcessId}|{InstanceId}|{InstallationId}|{LaunchNonce}";

        public static PeerIdentity Parse(string[] parts, int offset)
        {
            if (parts.Length < offset + 4 ||
                !int.TryParse(parts[offset], out var processId) || processId <= 0 ||
                parts[offset + 1].Length != 32 || parts[offset + 2].Length != 32 || parts[offset + 3].Length != 64)
            {
                throw new InvalidOperationException("Invalid parent-provisioned peer identity tuple.");
            }

            _ = Convert.FromHexString(parts[offset + 1]);
            _ = Convert.FromHexString(parts[offset + 2]);
            _ = Convert.FromHexString(parts[offset + 3]);
            return new PeerIdentity(processId, parts[offset + 1], parts[offset + 2], parts[offset + 3]);
        }
    }

    private sealed record WorkerReady(PeerIdentity Identity, string OwnerSessionId);
    private sealed record SessionEvidence(string OwnerSessionId, int ProcessId, string InstanceId, string InstallationId);
    private sealed record PairEvidence(PeerIdentity Owner, PeerIdentity Peer, string OwnerSessionId);
    private sealed record RenewRaceResult(int Successes, int Refusals);
    private sealed record RenewResult(bool Success, long Epoch, string Fence);
    private sealed record LeaseSnapshot(string LeaseId, long Epoch, string Fence);

    private sealed class ProbeChannel(GrpcChannel channel, ConcurrentQueue<int> peerProcessIds) : IAsyncDisposable, IDisposable
    {
        public GrpcChannel Channel { get; } = channel;
        public IReadOnlyCollection<int> PeerProcessIds => peerProcessIds.ToArray();

        public void Dispose() => Channel.Dispose();

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ClientSession(
        ProbeChannel channel,
        LocalBootstrapService.LocalBootstrapServiceClient client,
        byte[] launchNonce,
        PeerIdentity peer,
        byte[] leaseId,
        Metadata confirmHeaders) : IAsyncDisposable
    {
        private readonly object _gate = new();
        private long _epoch = ParseEpoch(confirmHeaders);
        private string _fence = ParseFence(confirmHeaders);

        public ProbeChannel Channel { get; } = channel;
        public LocalBootstrapService.LocalBootstrapServiceClient Client { get; } = client;
        public byte[] LaunchNonce { get; } = launchNonce;
        public PeerIdentity Peer { get; } = peer;
        public long Epoch { get { lock (_gate) return _epoch; } }
        public string Fence { get { lock (_gate) return _fence; } }
        public string LeaseId { get; } = Convert.ToHexString(leaseId);

        public LeaseSnapshot SnapshotLease()
        {
            lock (_gate)
            {
                return new LeaseSnapshot(LeaseId, _epoch, _fence);
            }
        }

        public void UpdateLease(long epoch, string fence)
        {
            lock (_gate)
            {
                if (epoch >= _epoch)
                {
                    _epoch = epoch;
                    _fence = fence;
                }
            }
        }

        private static long ParseEpoch(Metadata headers)
        {
            if (!long.TryParse(headers.GetValue("x-af-lease-epoch"), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var epoch) || epoch != 1)
            {
                throw new InvalidOperationException("Confirm returned an invalid initial lease epoch.");
            }

            return epoch;
        }

        private static string ParseFence(Metadata headers)
        {
            var fence = headers.GetValue("x-af-lease-fence");
            if (fence is null || fence.Length != 64)
            {
                throw new InvalidOperationException("Confirm returned an invalid initial lease fence.");
            }

            _ = Convert.FromHexString(fence);
            return fence;
        }

        public ValueTask DisposeAsync() => Channel.DisposeAsync();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxPeerCredentials
    {
        public int ProcessId;
        public uint UserId;
        public uint GroupId;
    }

    private static partial class NativeMethods
    {
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);

        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        [LibraryImport("libc", EntryPoint = "getsockopt", SetLastError = true)]
        internal static partial int GetSocketOption(SafeSocketHandle socket, int level, int option, out LinuxPeerCredentials value, ref uint valueLength);
    }
}

internal sealed class BootstrapState(
    byte[] secret,
    EndpointManifest manifest,
    Guid instanceId,
    byte[] launchNonce,
    string ownerSessionId)
{
    private readonly object _gate = new();
    private readonly Dictionary<string, LeaseState> _leases = new(StringComparer.Ordinal);
    private byte[]? _secret = secret;
    private int _confirmedDirections;
    private int _challengeDispatchCount;
    private TaskCompletionSource _bothDirectionsAuthenticated = NewSignal();
    private TaskCompletionSource _peerRenewalObserved = NewSignal();
    private RenewalExpiryRace? _expiryRace;

    public EndpointManifest Manifest { get; } = manifest;
    public Guid InstanceId { get; } = instanceId;
    public byte[] LaunchNonce { get; } = launchNonce;
    public string OwnerSessionId { get; } = ownerSessionId;
    public ConcurrentDictionary<string, PendingChallenge> Challenges { get; } = new(StringComparer.Ordinal);
    public TaskCompletionSource BothDirectionsAuthenticated => _bothDirectionsAuthenticated;
    public TaskCompletionSource CancellationObserved { get; } = NewSignal();
    public TaskCompletionSource PeerRenewalObserved => _peerRenewalObserved;
    public RenewalExpiryRace? ExpiryRace { get { lock (_gate) return _expiryRace; } }
    public Program.PeerIdentity? ExpectedPeer { get; private set; }
    public int ChallengeDispatchCount => Volatile.Read(ref _challengeDispatchCount);

    public byte[] Secret => Volatile.Read(ref _secret) ?? throw new InvalidOperationException("The one-use bootstrap secret has been destroyed.");

    public void SetExpectedPeer(Program.PeerIdentity peer)
    {
        lock (_gate)
        {
            ExpectedPeer = peer;
        }
    }

    public void BeginPeerEpoch(byte[] secret, Program.PeerIdentity peer)
    {
        lock (_gate)
        {
            if (_leases.Count != 0)
            {
                throw new InvalidOperationException("Cannot reattach while an old owner-session lease is still active.");
            }

            var previous = _secret;
            _secret = secret.ToArray();
            if (previous is not null)
            {
                CryptographicOperations.ZeroMemory(previous);
            }

            Challenges.Clear();
            _confirmedDirections = 0;
            _bothDirectionsAuthenticated = NewSignal();
            _peerRenewalObserved = NewSignal();
            _expiryRace = null;
            ExpectedPeer = peer;
        }
    }

    public void MarkChallengeDispatched() => Interlocked.Increment(ref _challengeDispatchCount);

    public void ClearSecrets()
    {
        lock (_gate)
        {
            var secret = _secret;
            _secret = null;
            if (secret is not null)
            {
                CryptographicOperations.ZeroMemory(secret);
            }

            CryptographicOperations.ZeroMemory(LaunchNonce);
        }
    }

    public void MarkClientAuthenticated() => MarkDirectionAuthenticated();

    public void MarkServerAuthenticated() => MarkDirectionAuthenticated();

    private void MarkDirectionAuthenticated()
    {
        lock (_gate)
        {
            _confirmedDirections++;
            if (_confirmedDirections == 2)
            {
                var previous = _secret;
                _secret = null;
                if (previous is not null)
                {
                    CryptographicOperations.ZeroMemory(previous);
                }

                _bothDirectionsAuthenticated.TrySetResult();
            }
        }
    }

    public LeaseState AddLease(string connectionId)
    {
        var leaseIdBytes = RandomNumberGenerator.GetBytes(32);
        var fenceBytes = RandomNumberGenerator.GetBytes(32);
        var lease = new LeaseState(
            Convert.ToHexString(leaseIdBytes),
            1,
            Convert.ToHexString(fenceBytes),
            DateTimeOffset.UtcNow.AddSeconds(30));
        CryptographicOperations.ZeroMemory(leaseIdBytes);
        CryptographicOperations.ZeroMemory(fenceBytes);
        lock (_gate)
        {
            _leases[connectionId] = lease;
        }

        return lease;
    }

    public void RemoveLease(string connectionId, string leaseId)
    {
        lock (_gate)
        {
            if (_leases.TryGetValue(connectionId, out var current) && current.LeaseId == leaseId)
            {
                _leases.Remove(connectionId);
            }
        }
    }

    public bool TryRenew(
        string connectionId,
        string leaseId,
        long requestedEpoch,
        string requestedFence,
        out LeaseState current)
    {
        lock (_gate)
        {
            if (!_leases.TryGetValue(connectionId, out var existing))
            {
                current = ExpiredLease;
                return false;
            }

            var fenceMatches = TryFixedHexEquals(existing.Fence, requestedFence);
            if (existing.LeaseId != leaseId || existing.Epoch != requestedEpoch || !fenceMatches || existing.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                current = existing;
                return false;
            }

            var nextFence = RandomNumberGenerator.GetBytes(32);
            current = existing with
            {
                Epoch = checked(existing.Epoch + 1),
                Fence = Convert.ToHexString(nextFence),
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(30),
            };
            CryptographicOperations.ZeroMemory(nextFence);
            _leases[connectionId] = current;
            return true;
        }
    }

    public void ArmExpiryRace(int expectedCalls, TimeSpan delay)
    {
        if (expectedCalls < 2 || expectedCalls > 32 || delay <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedCalls));
        }

        lock (_gate)
        {
            if (_leases.Count != 1)
            {
                throw new InvalidOperationException($"Expected one authenticated peer lease before race setup, found {_leases.Count}.");
            }

            var pair = _leases.Single();
            var expiresAt = DateTimeOffset.UtcNow.Add(delay);
            _leases[pair.Key] = pair.Value with { ExpiresAt = expiresAt };
            _expiryRace = new RenewalExpiryRace(pair.Value.LeaseId, expectedCalls, expiresAt);
        }
    }

    public RenewalExpiryRace? GetExpiryRace(string leaseId)
    {
        lock (_gate)
        {
            return _expiryRace is { } race && race.LeaseId == leaseId ? race : null;
        }
    }

    public void MarkRenewalObserved() => _peerRenewalObserved.TrySetResult();

    public async Task WaitForNoActiveLeasesAsync(TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        while (true)
        {
            lock (_gate)
            {
                if (_leases.Count == 0)
                {
                    return;
                }
            }

            await Task.Delay(TimeSpan.FromMilliseconds(20), cancellation.Token).ConfigureAwait(false);
        }
    }

    private static bool TryFixedHexEquals(string expected, string actual)
    {
        try
        {
            var expectedBytes = Convert.FromHexString(expected);
            var actualBytes = Convert.FromHexString(actual);
            var equal = expectedBytes.Length == actualBytes.Length && CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
            CryptographicOperations.ZeroMemory(expectedBytes);
            CryptographicOperations.ZeroMemory(actualBytes);
            return equal;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static LeaseState ExpiredLease { get; } = new(string.Empty, 0, new string('0', 64), DateTimeOffset.MinValue);
}

internal sealed record LeaseState(string LeaseId, long Epoch, string Fence, DateTimeOffset ExpiresAt);

internal sealed record PendingChallenge(
    string ConnectionId,
    byte[] ClientChallenge,
    byte[] ServerChallenge,
    byte[] ClientInstanceId,
    EndpointManifest Caller,
    DateTimeOffset ExpiresAt);

internal sealed class RenewalExpiryRace(string leaseId, int expectedCalls, DateTimeOffset expiresAt)
{
    private int _arrived;

    public string LeaseId { get; } = leaseId;
    public int ExpectedCalls { get; } = expectedCalls;
    public DateTimeOffset ExpiresAt { get; } = expiresAt;
    public TaskCompletionSource Arrived { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public async Task WaitAsync()
    {
        if (Interlocked.Increment(ref _arrived) == ExpectedCalls)
        {
            Arrived.TrySetResult();
        }

        await Release.Task.ConfigureAwait(false);
    }
}

internal sealed class LocalBootstrapProbeService(BootstrapState state) : LocalBootstrapService.LocalBootstrapServiceBase
{
    public override async Task<LocalBootstrapServiceChallengeResponse> Challenge(
        LocalBootstrapServiceChallengeRequest request,
        ServerCallContext context)
    {
        state.MarkChallengeDispatched();
        if (request.Challenge.Length == 32 && request.Challenge.Span[0] == 0xEE)
        {
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, context.CancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
            {
                state.CancellationObserved.TrySetResult();
                throw;
            }
        }

        if (!ContractShapeValidation.IsValid(request) ||
            !request.InstanceId.Value.Span.SequenceEqual(request.Caller.InstanceId.Value.Span) ||
            !Program.MatchesExpectedPeer(state, context, request.Caller))
        {
            return new LocalBootstrapServiceChallengeResponse
            {
                Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
                Error = UnauthorizedError(request.Meta.CorrelationId),
            };
        }

        var connectionId = context.GetHttpContext().Connection.Id;
        var challengeId = Guid.NewGuid();
        var serverChallenge = RandomNumberGenerator.GetBytes(32);
        var expiresAt = DateTimeOffset.UtcNow.AddSeconds(4);
        state.Challenges[Convert.ToHexString(Program.GuidBytes(challengeId))] = new PendingChallenge(
            connectionId,
            request.Challenge.ToByteArray(),
            serverChallenge,
            request.InstanceId.Value.ToByteArray(),
            request.Caller,
            expiresAt);
        await context.WriteResponseHeadersAsync(Program.LaunchResponseHeaders(state.LaunchNonce)).ConfigureAwait(false);

        return new LocalBootstrapServiceChallengeResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Value = new LocalBootstrapServiceChallengeValue
            {
                ChallengeId = Program.ToId(challengeId),
                ServerChallenge = ByteString.CopyFrom(serverChallenge),
                ExpiresAt = ToInstant(expiresAt),
                Server = state.Manifest,
            },
        };
    }

    public override async Task<LocalBootstrapServiceConfirmResponse> Confirm(
        LocalBootstrapServiceConfirmRequest request,
        ServerCallContext context)
    {
        var connectionId = context.GetHttpContext().Connection.Id;
        var key = Convert.ToHexString(request.ChallengeId.Value.Span);
        if (!ContractShapeValidation.IsValid(request) || !state.Challenges.TryRemove(key, out var challenge) ||
            challenge.ConnectionId != connectionId || challenge.ExpiresAt <= DateTimeOffset.UtcNow ||
            !Program.MatchesExpectedPeer(state, context, challenge.Caller))
        {
            return UnauthorizedConfirm(request.Meta.CorrelationId);
        }

        var expectedProof = Program.BootstrapProof(
            state.Secret,
            request.ChallengeId.Value.Span,
            challenge.ClientChallenge,
            challenge.ServerChallenge,
            challenge.ClientInstanceId,
            state.Manifest.InstanceId.Value.Span);
        var valid = CryptographicOperations.FixedTimeEquals(expectedProof, request.Proof.Span);
        CryptographicOperations.ZeroMemory(expectedProof);
        CryptographicOperations.ZeroMemory(challenge.ClientChallenge);
        CryptographicOperations.ZeroMemory(challenge.ServerChallenge);
        if (!valid)
        {
            return UnauthorizedConfirm(request.Meta.CorrelationId);
        }

        var lease = state.AddLease(connectionId);
        context.GetHttpContext().Features.Get<IConnectionLifetimeFeature>()?.ConnectionClosed.Register(() => state.RemoveLease(connectionId, lease.LeaseId));
        await context.WriteResponseHeadersAsync(Program.LeaseResponseHeaders(lease.Epoch, lease.Fence)).ConfigureAwait(false);
        state.MarkServerAuthenticated();
        return new LocalBootstrapServiceConfirmResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Value = new LocalBootstrapServiceConfirmValue
            {
                PeerNonce = ByteString.CopyFrom(Convert.FromHexString(lease.LeaseId)),
                ExpiresAt = ToInstant(lease.ExpiresAt),
            },
        };
    }

    public override async Task<LocalBootstrapServiceRenewResponse> Renew(
        LocalBootstrapServiceRenewRequest request,
        ServerCallContext context)
    {
        var http = context.GetHttpContext();
        var connectionId = http.Connection.Id;
        var leaseId = context.RequestHeaders.GetValue("x-af-lease-id") ?? string.Empty;
        var leaseEpochHeader = context.RequestHeaders.GetValue("x-af-lease-epoch");
        var leaseFence = context.RequestHeaders.GetValue("x-af-lease-fence") ?? string.Empty;
        _ = long.TryParse(leaseEpochHeader, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var requestedEpoch);

        var validRequest = ContractShapeValidation.IsValid(request) && Program.MatchesExpectedTransportPeer(state, context);
        var race = validRequest ? state.GetExpiryRace(leaseId) : null;
        if (race is not null)
        {
            await race.WaitAsync().ConfigureAwait(false);
        }

        var currentLease = new LeaseState(string.Empty, 0, new string('0', 64), DateTimeOffset.MinValue);
        var renewed = validRequest && state.TryRenew(connectionId, leaseId, requestedEpoch, leaseFence, out currentLease);
        if (!renewed && validRequest)
        {
            _ = state.TryRenew(connectionId, leaseId, requestedEpoch, leaseFence, out currentLease);
        }

        await context.WriteResponseHeadersAsync(Program.LeaseResponseHeaders(currentLease.Epoch, currentLease.Fence)).ConfigureAwait(false);
        if (!renewed)
        {
            return new LocalBootstrapServiceRenewResponse
            {
                Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
                Error = UnauthorizedError(request.Meta.CorrelationId),
            };
        }

        state.MarkRenewalObserved();
        return new LocalBootstrapServiceRenewResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Value = new LocalBootstrapServiceRenewValue { ExpiresAt = ToInstant(currentLease.ExpiresAt) },
        };
    }

    private static LocalBootstrapServiceConfirmResponse UnauthorizedConfirm(Id correlation) => new()
    {
        Meta = new ResponseMeta { CorrelationId = correlation },
        Error = UnauthorizedError(correlation),
    };

    private static ArcError UnauthorizedError(Id correlation) => new()
    {
        Code = "auth.unauthorized",
        Category = ErrorCategory.Authentication,
        MessageKey = "local.bootstrap.unauthorized",
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Effect = EffectCertainty.DidNotHappen,
        CorrelationId = correlation,
        Details = new ErrorDetails(),
    };

    private static Instant ToInstant(DateTimeOffset value) => new()
    {
        UnixSeconds = value.ToUnixTimeSeconds(),
        Nanos = (uint)(value.UtcTicks % TimeSpan.TicksPerSecond * 100),
    };
}
