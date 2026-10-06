// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Platform.Shapes;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using ArcForges.LocalRpc;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Core.Interceptors;

/// <summary>
/// Actual shared production parent/child composition. The probe launches its own AOT child and uses real private OS streams,
/// generated messages, launch authority, registration and lifecycle. It is not a restricted-launch or wrong-user isolation proof.
/// The separate historical bidirectional/OS peer-PID fixture remains intact.
/// </summary>
internal static class ProductionBootstrapProbe
{
    private const string BuildId = "prf04-production-bootstrap";
    private const int MaximumResourceBytes = 65536;

    internal static async Task RunAsync()
    {
        RequireAot();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        var cancellation = deadline.Token;
        var directory = Directory.CreateTempSubdirectory("afprf04-production-");
        try
        {
            var authority = LocalRpcLaunchAuthority.Create(Path.Combine(directory.FullName, "runtime"));
            await using var authorityLifetime = authority.ConfigureAwait(false);
            var identity = ActualIdentity();
            var parentInstance = Guid.NewGuid();
            var normal = await Round.StartAsync(authority, identity, parentInstance, false, cancellation).ConfigureAwait(false);
            await using (normal.ConfigureAwait(false))
            {
                await normal.DisconnectAsync(cancellation).ConfigureAwait(false);
            }
            var old = await Round.StartAsync(authority, identity, parentInstance, false, cancellation).ConfigureAwait(false);
            await using (old.ConfigureAwait(false))
            {
                var fresh = await Round.StartAsync(authority, identity, parentInstance, false, cancellation).ConfigureAwait(false);
                await using var freshLifetime = fresh.ConfigureAwait(false);
                Require(fresh.Instance != old.Instance && fresh.Launch.Descriptor.Epoch > old.Launch.Descriptor.Epoch,
                    "A relaunched child must have a fresh instance and launch epoch.");
                await old.Host.Completion.WaitAsync(cancellation).ConfigureAwait(false);
                Require(old.Launch.Revoked.IsCancellationRequested, "Supersession must revoke the old launch.");
                await old.CommandAsync(2, cancellation).ConfigureAwait(false);
                Require(await old.ReadAsync(cancellation).ConfigureAwait(false) == "OLD_REFUSED", "Old credentials must fail after supersession.");
                await old.StopAsync(cancellation).ConfigureAwait(false);
                await fresh.DisconnectAsync(cancellation).ConfigureAwait(false);
            }
            var rejected = await Round.StartAsync(authority, identity, parentInstance, true, cancellation).ConfigureAwait(false);
            await using (rejected.ConfigureAwait(false))
            {
                await rejected.Host.Completion.WaitAsync(cancellation).ConfigureAwait(false);
                Require(rejected.Host.Registration.EndReason == LocalRpcRegistrationEnd.ProofRejected
                    && rejected.Launch.Revoked.IsCancellationRequested, "Rejected proof must revoke and stop the actual host.");
                await rejected.StopAsync(cancellation).ConfigureAwait(false);
            }
            Console.WriteLine($"PASS actual production bootstrap Native AOT parent/child; transport={(OperatingSystem.IsWindows() ? "pipe" : "uds")}; generated auth/HMAC/refusal/cancellation/concurrent-idempotent-renewal/disconnect/relaunch/cleanup; no OS isolation claim.");
        }
        finally { directory.Delete(recursive: true); }
    }

    internal static async Task RunWorkerAsync(bool badProof)
    {
        RequireAot();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        var cancellation = deadline.Token;
        using var input = Console.OpenStandardInput();
        var header = new byte[20];
        await input.ReadExactlyAsync(header, cancellation).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        Require(length > LocalRpcLaunchDescriptor.SecretLength && length <= MaximumResourceBytes, "Invalid bounded private bootstrap resource.");
        var parentInstance = new Guid(header.AsSpan(4), bigEndian: true);
        var resource = new byte[length];
        try
        {
            await input.ReadExactlyAsync(resource, cancellation).ConfigureAwait(false);
            using var child = LocalRpcChildBootstrap.FromResource(resource);
            var actual = ActualIdentity();
            Require(child.Identity.BuildId == actual.BuildId && child.Identity.ProtocolVersion == actual.ProtocolVersion
                && CryptographicOperations.FixedTimeEquals(child.Identity.BuildDigest.Span, actual.BuildDigest.Span)
                && CryptographicOperations.FixedTimeEquals(child.Identity.ContractSetDigest.Span, actual.ContractSetDigest.Span),
                "Child must describe its actual probe build and contract.");
            using var parent = Process.GetProcessById(child.Descriptor.Parent.ProcessId);
            var observedParent = LocalRpcProcessIdentity.FromProcess(parent);
            Require(!parent.HasExited && observedParent.ProcessId == child.Descriptor.Parent.ProcessId
                && Math.Abs(observedParent.StartTimeUtcTicks - child.Descriptor.Parent.StartTimeUtcTicks) <= TimeSpan.FromSeconds(2).Ticks,
                "Actual launching parent required.");
            var endpoint = child.Descriptor.Endpoint ?? throw new InvalidOperationException("Actual private endpoint required.");
            var channel = LocalRpcClientChannel.Create(endpoint);
            await using var channelLifetime = channel.ConfigureAwait(false);
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
            var manifest = Manifest(child.Identity, child.InstanceId, endpoint);
            var malformed = new LocalBootstrapServiceChallengeRequest
            {
                Meta = null, Caller = manifest, InstanceId = ToId(child.InstanceId), Challenge = ByteString.CopyFrom(child.ClientChallenge.Span),
            };
            await ExpectRefusalAsync(() => client.ChallengeAsync(malformed, cancellationToken: cancellation).ResponseAsync).ConfigureAwait(false);
            using (var cancelled = new CancellationTokenSource())
            {
                await cancelled.CancelAsync().ConfigureAwait(false);
                try
                {
                    await client.ChallengeAsync(new(), cancellationToken: cancelled.Token);
                    throw new InvalidOperationException("A precancelled generated call was accepted.");
                }
                catch (RpcException error) when (error.StatusCode == StatusCode.Cancelled) { }
                catch (OperationCanceledException) { }
            }
            var challenge = await client.ChallengeAsync(new()
            {
                Meta = Meta(), Caller = manifest, InstanceId = ToId(child.InstanceId), Challenge = ByteString.CopyFrom(child.ClientChallenge.Span),
            }, cancellationToken: cancellation);
            Require(ContractShapeValidation.IsValid(challenge)
                && FromId(challenge.Value.Server.InstanceId) == parentInstance
                && challenge.Value.Server.ProcessId == (ulong)parent.Id
                && Math.Abs(FromInstant(challenge.Value.Server.ProcessStartedAt).UtcTicks - parent.StartTime.ToUniversalTime().Ticks)
                    <= TimeSpan.FromSeconds(2).Ticks, "The actual complete parent manifest must return.");
            var proof = child.ComputeProof(FromId(challenge.Value.ChallengeId), challenge.Value.ServerChallenge.Span, parentInstance);
            LocalBootstrapServiceConfirmResponse confirmation;
            try
            {
                var request = new LocalBootstrapServiceConfirmRequest
                {
                    Meta = Meta(), ChallengeId = challenge.Value.ChallengeId,
                    Proof = ByteString.CopyFrom(badProof ? new byte[32] : proof),
                };
                if (badProof)
                {
                    // Rejected proof revokes and stops the real host; shutdown may close transport before its refusal arrives.
                    // The parent separately requires the actual ProofRejected terminal state and revoked launch.
                    await ExpectRefusalAsync(() => client.ConfirmAsync(request, cancellationToken: cancellation).ResponseAsync, revokedHost: true).ConfigureAwait(false);
                    Console.WriteLine("BAD_PROOF_REFUSED");
                    await WaitStopAsync(input, cancellation).ConfigureAwait(false);
                    return;
                }
                confirmation = await client.ConfirmAsync(request, cancellationToken: cancellation);
            }
            finally { CryptographicOperations.ZeroMemory(proof); }
            Require(ContractShapeValidation.IsValid(confirmation), "Actual complete confirmation required.");
            using var credentials = child.AcceptGrant(confirmation.Value.PeerNonce.Span);
            var registered = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker.Intercept(credentials));
            await ExpectRefusalAsync(() => client.RenewAsync(new() { Meta = Meta() }, cancellationToken: cancellation).ResponseAsync).ConfigureAwait(false);
            var noCommand = Meta();
            noCommand.CommandId = null;
            await ExpectRefusalAsync(() => registered.RenewAsync(new() { Meta = noCommand }, cancellationToken: cancellation).ResponseAsync).ConfigureAwait(false);
            var command = ToId(Guid.NewGuid());
            var renewals = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            {
                var meta = Meta();
                meta.CommandId = command.Clone();
                return RenewWithBackoffAsync(registered, new() { Meta = meta }, cancellation);
            })).ConfigureAwait(false);
            Require(renewals.All(ContractShapeValidation.IsValid) && renewals.All(value => value.Value.ExpiresAt.Equals(renewals[0].Value.ExpiresAt)),
                "Concurrent retries of one command must share the actual idempotent lease expiry.");
            Console.WriteLine("REGISTERED|" + child.InstanceId.ToString("N"));
            var operation = await ReadCommandAsync(input, cancellation).ConfigureAwait(false);
            if (operation == 2)
            {
                try
                {
                    await registered.RenewAsync(new() { Meta = Meta() }, cancellationToken: cancellation);
                    throw new InvalidOperationException("Superseded credentials remained usable.");
                }
                catch (RpcException error) when (error.StatusCode is StatusCode.Unauthenticated or StatusCode.Unavailable or StatusCode.Cancelled) { }
                Console.WriteLine("OLD_REFUSED");
            }
            else Require(operation == 1, "Expected actual disconnect command.");
            await channel.DisposeAsync().ConfigureAwait(false);
            if (operation == 1) Console.WriteLine("DISCONNECTED");
            await WaitStopAsync(input, cancellation).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(resource); }
    }

    private static LocalRpcLaunchIdentity ActualIdentity()
    {
        using var executable = File.OpenRead(Environment.ProcessPath ?? throw new InvalidOperationException("Actual executable required."));
        // The digest identifies this probe's real generated contract, not a signed commercial contract-set catalogue.
        return new(LocalRpcChildKind.Connector, BuildId, SHA256.HashData(executable), 1,
            SHA256.HashData(PlatformReflection.Descriptor.SerializedData.Span));
    }

    private static EndpointManifest Manifest(LocalRpcLaunchIdentity identity, Guid instance, LocalRpcEndpoint endpoint)
    {
        using var process = Process.GetCurrentProcess();
        return new()
        {
            SchemaVersion = "1", AppId = identity.BuildId, InstallationId = ToId(Guid.NewGuid()), InstanceId = ToId(instance),
            ProcessId = (ulong)process.Id, ProcessStartedAt = ToInstant(new DateTimeOffset(process.StartTime.ToUniversalTime())),
            Endpoint = new() { Transport = endpoint.Transport == LocalRpcTransport.NamedPipe ? "pipe" : "uds", Address = endpoint.Address, InstanceId = ToId(instance) },
            BuildHash = Convert.ToHexStringLower(identity.BuildDigest.Span), ContractSetHash = Convert.ToHexStringLower(identity.ContractSetDigest.Span),
            ContractMajors = { identity.ProtocolVersion },
        };
    }

    private static async Task ExpectRefusalAsync<T>(Func<Task<T>> operation, bool revokedHost = false)
    {
        try { await operation().ConfigureAwait(false); }
        catch (RpcException error) when (error.StatusCode == StatusCode.Unauthenticated
            || (revokedHost && error.StatusCode is StatusCode.Unavailable or StatusCode.Cancelled)) { return; }
        throw new InvalidOperationException("The actual generated service must refuse unauthorized/malformed input.");
    }

    private static async Task<LocalBootstrapServiceRenewResponse> RenewWithBackoffAsync(
        LocalBootstrapService.LocalBootstrapServiceClient client, LocalBootstrapServiceRenewRequest request, CancellationToken cancellation)
    {
        for (var attempt = 0; ; attempt++)
        {
            try { return await client.RenewAsync(request, cancellationToken: cancellation).ConfigureAwait(false); }
            catch (RpcException error) when (attempt < 6 && error.StatusCode == StatusCode.ResourceExhausted
                && LocalRpcRefusal.TryRead(error, out var refusal) && refusal?.Reason == LocalRpcRefusalReason.ControlBusy)
            {
                // The actual typed refusal proves zero dispatch. Keep the same command and respect both reserved control slots.
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(160, 10 * (1 << attempt))), cancellation).ConfigureAwait(false);
            }
        }
    }

    private static async Task<int> ReadCommandAsync(Stream input, CancellationToken cancellation)
    {
        var bytes = new byte[4];
        await input.ReadExactlyAsync(bytes, cancellation).ConfigureAwait(false);
        return BinaryPrimitives.ReadInt32LittleEndian(bytes);
    }
    private static async Task WaitStopAsync(Stream input, CancellationToken cancellation)
        => Require(await ReadCommandAsync(input, cancellation).ConfigureAwait(false) == 0, "Expected bounded stop command.");
    private static Id ToId(Guid value) => new() { Value = ByteString.CopyFrom(value.ToByteArray(bigEndian: true)) };
    private static Guid FromId(Id value) => new(value.Value.Span, bigEndian: true);
    private static Instant ToInstant(DateTimeOffset value) => new() { UnixSeconds = value.ToUnixTimeSeconds(), Nanos = (uint)(value.UtcTicks % TimeSpan.TicksPerSecond * 100) };
    private static DateTimeOffset FromInstant(Instant value) => DateTimeOffset.FromUnixTimeSeconds(value.UnixSeconds).AddTicks(value.Nanos / 100);
    private static RequestMeta Meta() => new() { CorrelationId = ToId(Guid.NewGuid()), CommandId = ToId(Guid.NewGuid()) };
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void RequireAot() => Require(!RuntimeFeature.IsDynamicCodeSupported, "Run the actual published Native AOT executable.");

    private sealed class Round(LocalRpcLaunch launch, LocalRpcParentBootstrapHost host, Process process, Guid instance) : IAsyncDisposable
    {
        internal LocalRpcLaunch Launch { get; } = launch;
        internal LocalRpcParentBootstrapHost Host { get; } = host;
        internal Guid Instance { get; private set; } = instance;

        internal static async Task<Round> StartAsync(LocalRpcLaunchAuthority authority, LocalRpcLaunchIdentity identity,
            Guid parentInstance, bool badProof, CancellationToken cancellation)
        {
            var launch = authority.Launch("production-child", identity);
            var endpoint = launch.Endpoint ?? throw new InvalidOperationException("Actual launch endpoint required.");
            var host = await LocalRpcParentBootstrapHost.StartAsync(launch, Manifest(identity, parentInstance, endpoint),
                LocalRpcServer.CreateBuilder(endpoint), cancellation).ConfigureAwait(false);
            Process process;
            try
            {
                var start = new ProcessStartInfo(Environment.ProcessPath!) { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                start.ArgumentList.Add("--production-bootstrap-worker");
                if (badProof) start.ArgumentList.Add("bad-proof");
                process = Process.Start(start) ?? throw new InvalidOperationException("The actual AOT child could not start.");
            }
            catch
            {
                await host.DisposeAsync().ConfigureAwait(false);
                throw;
            }
            try
            {
                launch.BindChild(LocalRpcProcessIdentity.FromProcess(process));
                var resource = launch.HandoffBootstrapResource();
                try
                {
                    Require(resource.Length <= MaximumResourceBytes, "Private resource exceeds probe framing bound.");
                    var header = new byte[20];
                    BinaryPrimitives.WriteInt32LittleEndian(header, resource.Length);
                    parentInstance.TryWriteBytes(header.AsSpan(4), bigEndian: true, out _);
                    await process.StandardInput.BaseStream.WriteAsync(header, cancellation).ConfigureAwait(false);
                    await process.StandardInput.BaseStream.WriteAsync(resource, cancellation).ConfigureAwait(false);
                    await process.StandardInput.BaseStream.FlushAsync(cancellation).ConfigureAwait(false);
                }
                finally { CryptographicOperations.ZeroMemory(resource); }
                var round = new Round(launch, host, process, Guid.Empty);
                var message = await round.ReadAsync(cancellation).ConfigureAwait(false);
                if (badProof)
                {
                    Require(message == "BAD_PROOF_REFUSED", "Actual rejected proof result required.");
                    return round;
                }
                Require(message.StartsWith("REGISTERED|", StringComparison.Ordinal)
                    && Guid.TryParseExact(message.AsSpan(11), "N", out _), "Actual registered child identity required.");
                Require(host.Registration.State == LocalRpcRegistrationState.Registered, "Actual registration must be active.");
                round.Instance = Guid.ParseExact(message.AsSpan(11), "N");
                return round;
            }
            catch
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                        await process.WaitForExitAsync(cleanup.Token).ConfigureAwait(false);
                    }
                }
                finally
                {
                    process.Dispose();
                    await host.DisposeAsync().ConfigureAwait(false);
                }
                throw;
            }
        }

        internal async Task<string> ReadAsync(CancellationToken cancellation)
        {
            var bytes = new byte[512];
            var count = 0;
            while (count < bytes.Length)
            {
                Require(await process.StandardOutput.BaseStream.ReadAsync(bytes.AsMemory(count, 1), cancellation).ConfigureAwait(false) == 1, "Child closed before its expected evidence.");
                if (bytes[count++] == (byte)'\n') return Encoding.UTF8.GetString(bytes.AsSpan(0, count - 1)).TrimEnd('\r');
            }
            throw new InvalidOperationException("Child evidence exceeds the closed framing bound.");
        }
        internal async Task CommandAsync(int value, CancellationToken cancellation)
        {
            var bytes = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
            await process.StandardInput.BaseStream.WriteAsync(bytes, cancellation).ConfigureAwait(false);
            await process.StandardInput.BaseStream.FlushAsync(cancellation).ConfigureAwait(false);
        }
        internal async Task DisconnectAsync(CancellationToken cancellation)
        {
            await CommandAsync(1, cancellation).ConfigureAwait(false);
            Require(await ReadAsync(cancellation).ConfigureAwait(false) == "DISCONNECTED", "Actual channel disconnect required.");
            await Host.Completion.WaitAsync(cancellation).ConfigureAwait(false);
            Require(Host.Registration.EndReason == LocalRpcRegistrationEnd.ConnectionLost && Launch.Revoked.IsCancellationRequested,
                "Actual disconnect must revoke and finish host cleanup while the child is still alive.");
            await StopAsync(cancellation).ConfigureAwait(false);
        }
        internal async Task StopAsync(CancellationToken cancellation)
        {
            await CommandAsync(0, cancellation).ConfigureAwait(false);
            await process.WaitForExitAsync(cancellation).ConfigureAwait(false);
            Require(process.ExitCode == 0, "Actual AOT child failed.");
        }
        public async ValueTask DisposeAsync()
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
                }
            }
            finally
            {
                process.Dispose();
                await Host.DisposeAsync().ConfigureAwait(false);
            }
        }
    }
}
