// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Platform.Shapes;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using Grpc.Core;
using Grpc.AspNetCore.Server;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Transport.NamedPipes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

internal static class Program
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
            var first = await RunPairAsync(executable, transport, directory, runId, "a", runUnauthorizedChecks: true)
                .ConfigureAwait(false);
            var second = await RunPairAsync(executable, transport, directory, runId, "b", runUnauthorizedChecks: false)
                .ConfigureAwait(false);
            if (first.InstanceIds.Intersect(second.InstanceIds).Any())
            {
                throw new InvalidOperationException("Reattached probe processes must have fresh instance identities.");
            }

            Console.WriteLine("PASS: two Native AOT processes completed bidirectional LocalBootstrap, generated gRPC calls, cancellation, disconnect/re-attach, malformed-input, unauthorized-peer and bounded-message checks.");
            Console.WriteLine($"Evidence: {transport}; reattached process IDs [{string.Join(",", second.ProcessIds)}]; fresh instance IDs [{string.Join(",", second.InstanceIds)}].");
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
        string runId,
        string round,
        bool runUnauthorizedChecks)
    {
        var sharedSecret = RandomNumberGenerator.GetBytes(32);
        var addressA = Address(transport, directory, runId, round, "a");
        var addressB = Address(transport, directory, runId, round, "b");
        using var processA = StartWorker(executable, "a", transport, addressA, addressB, sharedSecret);
        using var processB = StartWorker(executable, "b", transport, addressB, addressA, sharedSecret);

        try
        {
            var readyA = await ReadReadyAsync(processA).ConfigureAwait(false);
            var readyB = await ReadReadyAsync(processB).ConfigureAwait(false);

            if (runUnauthorizedChecks)
            {
                var dispatchesBeforeRogue = await ReadChallengeDispatchCountAsync(processB).ConfigureAwait(false);
                if (dispatchesBeforeRogue != 0)
                {
                    throw new InvalidOperationException("The target worker handled a challenge before the negative-input phase.");
                }

                var wrongSecret = RandomNumberGenerator.GetBytes(32);
                if (CryptographicOperations.FixedTimeEquals(wrongSecret, sharedSecret))
                {
                    wrongSecret[0] ^= 1;
                }

                using var rogue = StartRogue(executable, transport, addressB, wrongSecret);
                CryptographicOperations.ZeroMemory(wrongSecret);
                await SendCommandAsync(rogue, "GO").ConfigureAwait(false);
                var malformedResult = await ReadLineAsync(rogue, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
                if (malformedResult != "MALFORMED|refused")
                {
                    throw new InvalidOperationException("The malformed-input check did not report its refusal stage: " + malformedResult);
                }

                var dispatchesAfterMalformed = await ReadChallengeDispatchCountAsync(processB).ConfigureAwait(false);
                if (dispatchesAfterMalformed != dispatchesBeforeRogue + 1)
                {
                    throw new InvalidOperationException("The malformed protobuf request reached the Challenge service method.");
                }

                await SendCommandAsync(rogue, "CONTINUE").ConfigureAwait(false);
                var rogueResult = await ReadLineAsync(rogue, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
                if (rogueResult != "PASS unauthorized malformed recovered bounded")
                {
                    throw new InvalidOperationException("The same-user rogue process was not rejected or the channel failed to recover after malformed input: " + rogueResult);
                }

                await EnsureExitedAsync(rogue).ConfigureAwait(false);
                var dispatchesAfterRecovery = await ReadChallengeDispatchCountAsync(processB).ConfigureAwait(false);
                if (dispatchesAfterRecovery != dispatchesAfterMalformed + 1)
                {
                    throw new InvalidOperationException("A valid post-malformed Challenge call did not reach the service exactly once.");
                }
            }

            await SendCommandAsync(processA, $"GO|{readyB.ProcessId}|{readyB.InstanceId}").ConfigureAwait(false);
            await SendCommandAsync(processB, $"GO|{readyA.ProcessId}|{readyA.InstanceId}").ConfigureAwait(false);
            var doneA = await ReadLineAsync(processA, TimeSpan.FromSeconds(60)).ConfigureAwait(false);
            var doneB = await ReadLineAsync(processB, TimeSpan.FromSeconds(60)).ConfigureAwait(false);
            if (doneA != "PASS worker" || doneB != "PASS worker")
            {
                throw new InvalidOperationException($"Probe process failure: A='{doneA}', B='{doneB}'.");
            }

            await EnsureExitedAsync(processA).ConfigureAwait(false);
            await EnsureExitedAsync(processB).ConfigureAwait(false);
            return new PairEvidence([readyA.ProcessId, readyB.ProcessId], [readyA.InstanceId, readyB.InstanceId]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            KillIfRunning(processA);
            KillIfRunning(processB);
        }
    }

    private static string Address(string transport, string directory, string runId, string round, string side) =>
        transport == "pipe"
            ? $"afprf04-{runId}-{round}-{side}"
            : Path.Combine(directory, $"{round}-{side}.sock");

    private static Process StartWorker(string executable, string role, string transport, string ownAddress, string peerAddress, byte[] secret)
    {
        var process = Start(executable, "--worker", role, transport, ownAddress, peerAddress);
        WriteSecret(process, secret);
        return process;
    }

    private static Process StartRogue(string executable, string transport, string peerAddress, byte[] secret)
    {
        var process = Start(executable, "--rogue", transport, peerAddress);
        WriteSecret(process, secret);
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

    private static async Task<ReadyIdentity> ReadReadyAsync(Process process)
    {
        var line = await ReadLineAsync(process, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
        var parts = line.Split('|');
        if (parts.Length != 3 || parts[0] != "READY" || !int.TryParse(parts[1], out var processId))
        {
            throw new InvalidOperationException("Invalid process-ready record: " + line);
        }

        return new ReadyIdentity(processId, parts[2]);
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

    private static void WriteSecret(Process process, byte[] secret)
    {
        process.StandardInput.BaseStream.Write(secret);
        process.StandardInput.BaseStream.Flush();
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

    private static async Task<int> RunWorkerAsync(string[] args)
    {
        if (args.Length != 4)
        {
            throw new ArgumentException("Worker requires role, transport, endpoint address and peer address.");
        }

        var role = args[0];
        var transport = args[1];
        var ownAddress = args[2];
        var peerAddress = args[3];
        var control = Console.OpenStandardInput();
        var secret = new byte[32];
        await control.ReadExactlyAsync(secret).ConfigureAwait(false);
        using var controlReader = new StreamReader(control, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 256, leaveOpen: true);
        var instance = Guid.NewGuid();
        var ownManifest = CreateManifest(transport, ownAddress, instance);
        var state = new BootstrapState(secret, ownManifest, instance);
        var app = CreateServer(transport, ownAddress, state);
        await using (app.ConfigureAwait(false))
        {
            await app.StartAsync().ConfigureAwait(false);
            Console.WriteLine($"READY|{Environment.ProcessId}|{Convert.ToHexString(GuidBytes(instance))}");

            int expectedPeerPid;
            string expectedPeerInstance;
            while (true)
            {
                var command = await controlReader.ReadLineAsync().ConfigureAwait(false)
                    ?? throw new InvalidOperationException("Parent closed the private probe control stream before GO.");
                if (command == "COUNT")
                {
                    await Console.Out.WriteLineAsync($"CHALLENGE-DISPATCHES|{state.ChallengeDispatchCount}").ConfigureAwait(false);
                    continue;
                }

                var parts = command.Split('|');
                if (parts.Length != 3 || parts[0] != "GO" || !int.TryParse(parts[1], out expectedPeerPid))
                {
                    throw new InvalidOperationException("Invalid private probe control command.");
                }

                expectedPeerInstance = parts[2];
                break;
            }

            await RunClientChecksAsync(state, transport, peerAddress, expectedPeerPid, Convert.FromHexString(expectedPeerInstance))
                .ConfigureAwait(false);
            await state.BothDirectionsAuthenticated.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            await state.PeerRenewalObserved.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            await app.StopAsync().ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(secret);
            Console.WriteLine("PASS worker");
            return 0;
        }
    }

    private static async Task RunClientChecksAsync(
        BootstrapState state,
        string transport,
        string peerAddress,
        int expectedPeerPid,
        byte[] expectedPeerInstance)
    {
        using (var cancelChannel = CreateChannel(transport, peerAddress))
        {
            var cancelService = new LocalBootstrapService.LocalBootstrapServiceClient(cancelChannel);
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
            var request = NewChallengeRequest(state.Manifest, RandomNumberGenerator.GetBytes(32));
            request.Challenge = ByteString.CopyFrom([0xEE, .. new byte[31]]);
            try
            {
                _ = await cancelService.ChallengeAsync(request, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: cancellation.Token)
                    .ResponseAsync.ConfigureAwait(false);
                throw new InvalidOperationException("A canceled LocalBootstrap call unexpectedly completed.");
            }
            catch (RpcException exception) when (exception.StatusCode == StatusCode.Cancelled)
            {
                await state.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            }
        }

        using var channel = CreateChannel(transport, peerAddress);
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel);
        var clientChallenge = RandomNumberGenerator.GetBytes(32);
        var challengeResponse = await client.ChallengeAsync(
            NewChallengeRequest(state.Manifest, clientChallenge),
            deadline: DateTime.UtcNow.AddSeconds(5)).ResponseAsync.ConfigureAwait(false);
        if (challengeResponse.OutcomeCase != LocalBootstrapServiceChallengeResponse.OutcomeOneofCase.Value)
        {
            throw new InvalidOperationException("The peer did not issue a valid LocalBootstrap challenge.");
        }

        var server = challengeResponse.Value.Server;
        if (server.ProcessId != (ulong)expectedPeerPid ||
            !server.InstanceId.Value.Span.SequenceEqual(expectedPeerInstance) ||
            !server.Endpoint.InstanceId.Value.Span.SequenceEqual(expectedPeerInstance) ||
            server.Endpoint.Transport != transport ||
            server.Endpoint.Address != peerAddress ||
            server.AppId != "org.arcforges.prf04.probe" ||
            server.SchemaVersion != "1" ||
            server.ContractSetHash != state.Manifest.ContractSetHash ||
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
        var confirmResponse = await client.ConfirmAsync(
            new LocalBootstrapServiceConfirmRequest
            {
                Meta = NewMeta(),
                ChallengeId = challengeResponse.Value.ChallengeId,
                Proof = ByteString.CopyFrom(proof),
            },
            deadline: DateTime.UtcNow.AddSeconds(5)).ResponseAsync.ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(proof);
        if (confirmResponse.OutcomeCase != LocalBootstrapServiceConfirmResponse.OutcomeOneofCase.Value ||
            confirmResponse.Value.PeerNonce.Length != 32)
        {
            throw new InvalidOperationException("The peer refused the one-use LocalBootstrap confirmation.");
        }

        state.MarkClientAuthenticated();
        var renewResponse = await client.RenewAsync(
            new LocalBootstrapServiceRenewRequest { Meta = NewMeta() },
            deadline: DateTime.UtcNow.AddSeconds(5)).ResponseAsync.ConfigureAwait(false);
        if (renewResponse.OutcomeCase != LocalBootstrapServiceRenewResponse.OutcomeOneofCase.Value)
        {
            throw new InvalidOperationException("The same-connection LocalBootstrap lease renewal failed.");
        }

        if (!IsFutureBounded(renewResponse.Value.ExpiresAt, TimeSpan.FromSeconds(30)))
        {
            throw new InvalidOperationException("The renewed LocalBootstrap lease exceeded its 30-second bound or was already expired.");
        }
    }

    private static async Task<int> RunRogueAsync(string[] args)
    {
        if (args.Length != 2)
        {
            throw new ArgumentException("Rogue requires transport and peer address.");
        }

        var transport = args[0];
        var peerAddress = args[1];
        var control = Console.OpenStandardInput();
        var wrongSecret = new byte[32];
        await control.ReadExactlyAsync(wrongSecret).ConfigureAwait(false);
        using var controlReader = new StreamReader(control, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 256, leaveOpen: true);
        if (await controlReader.ReadLineAsync().ConfigureAwait(false) != "GO")
        {
            throw new InvalidOperationException("Parent closed the private rogue control stream before GO.");
        }

        var instance = Guid.NewGuid();
        using var channel = CreateChannel(transport, peerAddress);
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel);
        var clientChallenge = RandomNumberGenerator.GetBytes(32);
        var challengeResponse = await client.ChallengeAsync(
            NewChallengeRequest(CreateManifest(transport, "unauthorized", instance), clientChallenge),
            deadline: DateTime.UtcNow.AddSeconds(5)).ResponseAsync.ConfigureAwait(false);
        if (challengeResponse.OutcomeCase != LocalBootstrapServiceChallengeResponse.OutcomeOneofCase.Value)
        {
            throw new InvalidOperationException("The server did not challenge the unauthorized same-user peer.");
        }

        var forgedProof = BootstrapProof(
            wrongSecret,
            challengeResponse.Value.ChallengeId.Value.Span,
            clientChallenge,
            challengeResponse.Value.ServerChallenge.Span,
            GuidBytes(instance),
            challengeResponse.Value.Server.InstanceId.Value.Span);
        CryptographicOperations.ZeroMemory(clientChallenge);
        var denial = await client.ConfirmAsync(
            new LocalBootstrapServiceConfirmRequest
            {
                Meta = NewMeta(),
                ChallengeId = challengeResponse.Value.ChallengeId,
                Proof = ByteString.CopyFrom(forgedProof),
            },
            deadline: DateTime.UtcNow.AddSeconds(5)).ResponseAsync.ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(forgedProof);
        if (denial.OutcomeCase != LocalBootstrapServiceConfirmResponse.OutcomeOneofCase.Error ||
            denial.Error.Category != ErrorCategory.Authentication)
        {
            throw new InvalidOperationException("An invalid one-use HMAC proof was not explicitly refused.");
        }

        await VerifyMalformedInputAsync(channel).ConfigureAwait(false);
        await Console.Out.WriteLineAsync("MALFORMED|refused").ConfigureAwait(false);
        if (await controlReader.ReadLineAsync().ConfigureAwait(false) != "CONTINUE")
        {
            throw new InvalidOperationException("Parent did not continue the malformed-input recovery check.");
        }

        await VerifyNormalChallengeAsync(client, transport).ConfigureAwait(false);
        await VerifyBoundedInputAsync(client).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(wrongSecret);
        await Console.Out.WriteLineAsync("PASS unauthorized malformed recovered bounded").ConfigureAwait(false);
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

    private static GrpcChannel CreateChannel(string transport, string address)
    {
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
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };

        return GrpcChannel.ForAddress("http://arcforges.invalid", new GrpcChannelOptions
        {
            HttpHandler = handler,
            MaxSendMessageSize = MaximumMessageBytes + 64 * 1024,
            MaxReceiveMessageSize = MaximumMessageBytes,
        });
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

    private static EndpointManifest CreateManifest(string transport, string address, Guid instance)
    {
        using var process = Process.GetCurrentProcess();
        var descriptor = PlatformReflection.Descriptor.ToProto().ToByteArray();
        return new EndpointManifest
        {
            SchemaVersion = "1",
            AppId = "org.arcforges.prf04.probe",
            InstallationId = NewId(),
            InstanceId = ToId(instance),
            ProcessId = (ulong)Environment.ProcessId,
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

    private sealed record ReadyIdentity(int ProcessId, string InstanceId);
    private sealed record PairEvidence(int[] ProcessIds, string[] InstanceIds);
}

internal sealed class BootstrapState(byte[] secret, EndpointManifest manifest, Guid instanceId)
{
    private int _confirmedDirections;
    private int _challengeDispatchCount;
    private byte[]? _secret = secret;

    public EndpointManifest Manifest { get; } = manifest;
    public Guid InstanceId { get; } = instanceId;
    public ConcurrentDictionary<string, PendingChallenge> Challenges { get; } = new(StringComparer.Ordinal);
    public ConcurrentDictionary<string, byte[]> Leases { get; } = new(StringComparer.Ordinal);
    public TaskCompletionSource BothDirectionsAuthenticated { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public TaskCompletionSource CancellationObserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public TaskCompletionSource PeerRenewalObserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public int ChallengeDispatchCount => Volatile.Read(ref _challengeDispatchCount);

    public void MarkChallengeDispatched() => Interlocked.Increment(ref _challengeDispatchCount);

    public byte[] Secret => Volatile.Read(ref _secret) ?? throw new InvalidOperationException("The one-use bootstrap secret has been destroyed.");

    public void MarkClientAuthenticated() => MarkDirectionAuthenticated();

    public void MarkServerAuthenticated() => MarkDirectionAuthenticated();

    private void MarkDirectionAuthenticated()
    {
        if (Interlocked.Increment(ref _confirmedDirections) == 2)
        {
            var secret = Interlocked.Exchange(ref _secret, null);
            if (secret is not null)
            {
                CryptographicOperations.ZeroMemory(secret);
            }

            BothDirectionsAuthenticated.TrySetResult();
        }
    }
}

internal sealed record PendingChallenge(
    string ConnectionId,
    byte[] ClientChallenge,
    byte[] ServerChallenge,
    byte[] ClientInstanceId,
    DateTimeOffset ExpiresAt);

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
            !request.InstanceId.Value.Span.SequenceEqual(request.Caller.InstanceId.Value.Span))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "invalid bootstrap challenge"));
        }

        var connectionId = context.GetHttpContext().Connection.Id;
        var challengeId = Guid.NewGuid();
        var serverChallenge = RandomNumberGenerator.GetBytes(32);
        var expiresAt = DateTimeOffset.UtcNow.AddSeconds(4);
        state.Challenges[Convert.ToHexString(GuidBytes(challengeId))] = new PendingChallenge(
            connectionId,
            request.Challenge.ToByteArray(),
            serverChallenge,
            request.InstanceId.Value.ToByteArray(),
            expiresAt);

        return new LocalBootstrapServiceChallengeResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Value = new LocalBootstrapServiceChallengeValue
            {
                ChallengeId = ToId(challengeId),
                ServerChallenge = ByteString.CopyFrom(serverChallenge),
                ExpiresAt = ToInstant(expiresAt),
                Server = state.Manifest,
            },
        };
    }

    public override Task<LocalBootstrapServiceConfirmResponse> Confirm(
        LocalBootstrapServiceConfirmRequest request,
        ServerCallContext context)
    {
        var connectionId = context.GetHttpContext().Connection.Id;
        var key = Convert.ToHexString(request.ChallengeId.Value.Span);
        if (!ContractShapeValidation.IsValid(request) || !state.Challenges.TryRemove(key, out var challenge) ||
            challenge.ConnectionId != connectionId || challenge.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return Task.FromResult(Unauthorized(request.Meta.CorrelationId));
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
            return Task.FromResult(Unauthorized(request.Meta.CorrelationId));
        }

        var nonce = RandomNumberGenerator.GetBytes(32);
        state.Leases[connectionId] = nonce;
        state.MarkServerAuthenticated();
        return Task.FromResult(new LocalBootstrapServiceConfirmResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Value = new LocalBootstrapServiceConfirmValue
            {
                PeerNonce = ByteString.CopyFrom(nonce),
                ExpiresAt = ToInstant(DateTimeOffset.UtcNow.AddSeconds(30)),
            },
        });
    }

    public override Task<LocalBootstrapServiceRenewResponse> Renew(
        LocalBootstrapServiceRenewRequest request,
        ServerCallContext context)
    {
        var connectionId = context.GetHttpContext().Connection.Id;
        if (!ContractShapeValidation.IsValid(request) || !state.Leases.ContainsKey(connectionId))
        {
            return Task.FromResult(new LocalBootstrapServiceRenewResponse
            {
                Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
                Error = UnauthorizedError(request.Meta.CorrelationId),
            });
        }

        state.PeerRenewalObserved.TrySetResult();
        return Task.FromResult(new LocalBootstrapServiceRenewResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Value = new LocalBootstrapServiceRenewValue { ExpiresAt = ToInstant(DateTimeOffset.UtcNow.AddSeconds(30)) },
        });
    }

    private static LocalBootstrapServiceConfirmResponse Unauthorized(Id correlation) => new()
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

    private static byte[] GuidBytes(Guid value)
    {
        var bytes = new byte[16];
        value.TryWriteBytes(bytes, bigEndian: true, out _);
        return bytes;
    }

    private static Id ToId(Guid value) => new() { Value = ByteString.CopyFrom(GuidBytes(value)) };

    private static Instant ToInstant(DateTimeOffset value) => new()
    {
        UnixSeconds = value.ToUnixTimeSeconds(),
        Nanos = (uint)(value.UtcTicks % TimeSpan.TicksPerSecond * 100),
    };
}
