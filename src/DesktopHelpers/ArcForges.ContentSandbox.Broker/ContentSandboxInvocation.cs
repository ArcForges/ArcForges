// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using ArcForges.Foundation.Errors;
using ArcForges.LocalRpc;
using Grpc.Core;
using Grpc.Core.Interceptors;
using SandboxProfileCheck = ArcForges.Contracts.LocalRpc.Sandbox.SandboxProfile;

namespace ArcForges.ContentSandbox.Broker;

/// <summary>
/// One restricted helper process, registered and holding its one session, and the parent's side of everything that crosses to it: the
/// generated sandbox calls, the brokered buffers and the supervision. The helper never commits product state and nothing it returns is
/// trusted: shapes are checked again here, and the bytes of a tile are verified on the parent's own private copy. When the helper crashes, hangs,
/// exhausts its budget or loses its parent, the invocation ends, the parent keeps running unchanged, and the call fails with a typed reason.
/// </summary>
[SuppressMessage("Maintainability", "CA1506", Justification = "The invocation is the one parent-side owner of a helper's calls, buffers and supervision.")]
public sealed class ContentSandboxInvocation : IAsyncDisposable
{
    private static readonly TimeSpan RenewInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan CancelGrace = LocalRpcBrokerLimits.MaxCancelGrace;
    private static readonly TimeSpan CallMargin = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan MaxCall = TimeSpan.FromSeconds(30);

    private readonly ContentSandboxLaunchOptions _options;
    private readonly IProvisionedHelper _helper;
    private readonly LocalRpcLaunch _launch;
    private readonly LocalRpcRegistration _registration;
    private readonly LocalRpcServer _bootstrapServer;
    private readonly LocalRpcClientChannel _channel;
    private readonly ContentSandboxService.ContentSandboxServiceClient _client;
    private readonly LocalRpcBrokerRegistry _registry;
    private readonly SemaphoreSlim _operations = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Dictionary<Guid, ImageState> _images = [];
    private readonly Dictionary<Guid, uint> _documents = [];
    private readonly Guid _invocationId;
    private readonly Guid _leaseId;
    private readonly ulong _generation = 1;
    private readonly Task _supervision;
    private readonly TaskCompletionSource _renewalLost = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _stopSupervision = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private LocalRpcBrokerSession? _session;
    private Guid _sessionId;
    private int _closing;
    private int _terminated;
    private int _disposed;

    private ContentSandboxInvocation(
        ContentSandboxLaunchOptions options,
        IProvisionedHelper helper,
        LocalRpcLaunch launch,
        LocalRpcRegistration registration,
        LocalRpcServer bootstrapServer,
        LocalRpcClientChannel channel,
        ContentSandboxService.ContentSandboxServiceClient client,
        Guid invocationId,
        Guid leaseId)
    {
        _options = options;
        _helper = helper;
        _launch = launch;
        _registration = registration;
        _bootstrapServer = bootstrapServer;
        _channel = channel;
        _client = client;
        _invocationId = invocationId;
        _leaseId = leaseId;
        _registry = new LocalRpcBrokerRegistry();
        _supervision = Supervise();
    }

    /// <summary>The restricted helper process (id and start value) this invocation owns.</summary>
    public LocalRpcProcessIdentity HelperProcess => _helper.Identity;

    /// <summary>The last output the helper wrote to its standard output and error. Diagnostics only: never a parser result and never trusted.</summary>
    public string HelperDiagnostics => _helper.DiagnosticTail;

    /// <summary>The raw generated client, for the tests that must speak to the helper outside the typed operations.</summary>
    internal ContentSandboxService.ContentSandboxServiceClient RawClient => _client;

    /// <summary>The identifier of the one session of this invocation.</summary>
    internal Guid SessionId => _sessionId;

    /// <summary>The brokered session of this invocation.</summary>
    internal LocalRpcBrokerSession? BrokerSession => _session;

    /// <summary>True once the helper process has been ended or has ended: every later call fails.</summary>
    public bool IsEnded => Volatile.Read(ref _terminated) != 0 || _helper.Exited.IsCompleted;

    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the launch, registration, server and channel passes to the invocation, which disposes them; every failure path disposes what exists.")]
    internal static async Task<ContentSandboxResult<ContentSandboxInvocation>> StartAsync(
        ContentSandboxLaunchOptions options,
        IContentSandboxProcessLauncher launcher,
        LocalRpcLaunchAuthority authority,
        ReadOnlyMemory<byte> input,
        CancellationToken cancellationToken)
    {
        var invocationId = Guid.NewGuid();
        var leaseId = Guid.NewGuid();
        var inputId = Guid.NewGuid();
        var inputDigest = SHA256.HashData(input.Span);
        var slotName = "sandbox-" + invocationId.ToString("N")[..16];
        var limits = options.Limits;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.LaunchTimeout);
        LocalRpcLaunch? launch = null;
        LocalRpcRegistration? registration = null;
        LocalRpcServer? server = null;
        LocalRpcClientChannel? channel = null;
        IProvisionedHelper? helper = null;
        ContentSandboxInvocation? invocation = null;
        try
        {
            launch = authority.Launch(slotName, ContentSandboxLauncher.IdentityFor(options), LocalRpcLaunchTransport.SuppliedStreams);
            registration = LocalRpcRegistration.Create(launch);
            var resource = launch.HandoffBootstrapResource();
            var capacities = Enumerable.Repeat((long)options.SlotCapacityBytes, options.SlotCount).ToArray();
            var request = new HelperStartRequest(
                options.HelperPath,
                options.HelperSha256,
                input,
                capacities,
                limits,
                launch.BindChild,
                entries =>
                {
                    using var frame = new ContentSandboxLaunchFrame(
                        launcher.Profile,
                        invocationId,
                        leaseId,
                        1,
                        inputId,
                        (ulong)input.Length,
                        inputDigest,
                        [.. capacities.Select(capacity => (ulong)capacity)],
                        limits,
                        entries,
                        options.ParserProfile,
                        resource);
                    return frame.Encode();
                });
            helper = await launcher.StartAsync(request, timeout.Token).ConfigureAwait(false);

            var supplier = new LocalRpcStreamSupplier();
            if (!supplier.TrySupply(helper.ControlStream))
            {
                throw new ContentSandboxLaunchException("resource.unavailable", "The control stream was refused.");
            }

            server = LocalRpcServer.CreateBuilder(supplier)
                .RequireRegistration(registration)
                .AuthorizeConnectionsAsync(registration.AuthorizeConnectionAsync)
                .AddService(new BootstrapService())
                .Build();
            await server.StartAsync(timeout.Token).ConfigureAwait(false);
            await WaitRegisteredAsync(registration, helper, timeout.Token).ConfigureAwait(false);

            var declaration = new LocalRpcChildDeclaration(
                LocalRpcChildKind.ContentSandbox,
                [
                    new LocalRpcServiceDeclaration(LocalRpcRegistration.BootstrapService, [1]),
                    new LocalRpcServiceDeclaration(ContentSandboxContract.ServiceName, [1]),
                ]);
            var router = new LocalRpcRouter();
            router.Add(registration, declaration);
            if (router.TryResolve(new LocalRpcRouteRequest(slotName, ContentSandboxContract.ServiceName, 1), out var route) != LocalRpcRouteRefusal.None
                || route is null)
            {
                throw new ContentSandboxLaunchException("security.isolation_unavailable", "The helper declared no sandbox service.");
            }

            var serviceStream = helper.ServiceStream;
            channel = LocalRpcClientChannel.CreateFromStreams(_ => ValueTask.FromResult(serviceStream));
            var client = new ContentSandboxService.ContentSandboxServiceClient(channel.CallInvoker.Intercept(route.CreateGuard()));
            invocation = new ContentSandboxInvocation(options, helper, launch, registration, server, channel, client, invocationId, leaseId);
            var opened = await invocation.OpenSessionAsync(inputId, (ulong)input.Length, inputDigest, timeout.Token).ConfigureAwait(false);
            if (!opened.IsSuccess)
            {
                var failure = opened.Failure;
                await invocation.DisposeAsync().ConfigureAwait(false);
                return ContentSandboxResult<ContentSandboxInvocation>.Fail(failure);
            }

            return ContentSandboxResult<ContentSandboxInvocation>.Ok(invocation);
        }
        catch (Exception exception) when (exception is ContentSandboxLaunchException or OperationCanceledException or RpcException or IOException or InvalidOperationException)
        {
            if (invocation is not null)
            {
                await invocation.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                await DisposePartialAsync(helper, channel, server, registration, launch).ConfigureAwait(false);
            }

            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            var code = exception is ContentSandboxLaunchException launchFailure ? launchFailure.ReasonCode : ReasonForStartFailure(helper);
            return ContentSandboxResult<ContentSandboxInvocation>.Fail(code, Describe(exception, helper));
        }
    }

    /// <summary>Opens a decoded image of the input. The image keeps the identifier the parent mints here.</summary>
    /// <param name="subimage">The subimage index.</param>
    /// <param name="mip">The mip level.</param>
    /// <param name="outputFormat">1 for 8-bit RGBA tiles, 2 for 32-bit float RGBA tiles.</param>
    /// <param name="cancellationToken">Cancels the call, and with it the invocation.</param>
    public async ValueTask<ContentSandboxResult<Guid>> OpenImageAsync(uint subimage, uint mip, uint outputFormat, CancellationToken cancellationToken = default)
    {
        if (outputFormat is not (1 or 2))
        {
            return ContentSandboxResult<Guid>.Fail("validation.invalid_request");
        }

        return await RunAsync(
            async token =>
            {
                var imageId = Guid.NewGuid();
                var response = await _client.OpenImageAsync(
                    new ContentSandboxServiceOpenImageRequest
                    {
                        Meta = NewMeta(),
                        SessionId = SandboxRecords.ToWireId(_sessionId),
                        ImageId = SandboxRecords.ToWireId(imageId),
                        Subimage = subimage,
                        Mip = mip,
                        OutputFormat = outputFormat,
                    },
                    CallOptions(token)).ConfigureAwait(false);
                if (response.OutcomeCase != ContentSandboxServiceOpenImageResponse.OutcomeOneofCase.Value)
                {
                    return Failed<Guid>(response.Error);
                }

                if (!SandboxRecords.TryReadId(response.Value.ImageId, out var echoed) || echoed != imageId)
                {
                    return await EndedBecauseAsync<Guid>("resource.parser_failed").ConfigureAwait(false);
                }

                _images[imageId] = new ImageState(outputFormat, null);
                return ContentSandboxResult<Guid>.Ok(imageId);
            },
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads the bounded description of an opened image.</summary>
    /// <param name="imageId">The identifier returned by <see cref="OpenImageAsync"/>.</param>
    /// <param name="cancellationToken">Cancels the call, and with it the invocation.</param>
    public async ValueTask<ContentSandboxResult<SandboxImageInfo>> GetImageInfoAsync(Guid imageId, CancellationToken cancellationToken = default) =>
        await RunAsync(token => ImageInfoCoreAsync(imageId, token), cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Reads one tile of an opened image through a brokered output slot: the parent grants the slot, the helper fills only that grant and
    /// seals it, and the parent checks the seal against its own request, copies the bytes into private memory and verifies the digest on the copy.
    /// </summary>
    /// <param name="imageId">The identifier returned by <see cref="OpenImageAsync"/>.</param>
    /// <param name="x">The tile origin.</param>
    /// <param name="y">The tile origin.</param>
    /// <param name="width">The tile width in pixels, 1 through 2048.</param>
    /// <param name="height">The tile height in pixels, 1 through 2048.</param>
    /// <param name="cancellationToken">Cancels the call, and with it the invocation.</param>
    public async ValueTask<ContentSandboxResult<ContentSandboxTile>> ReadImageTileAsync(Guid imageId, uint x, uint y, uint width, uint height, CancellationToken cancellationToken = default) =>
        await RunAsync(
            async token =>
            {
                if (!_images.TryGetValue(imageId, out var state))
                {
                    return ContentSandboxResult<ContentSandboxTile>.Fail("state.not_found");
                }

                var info = await ImageInfoCoreAsync(imageId, token).ConfigureAwait(false);
                if (!info.IsSuccess)
                {
                    return ContentSandboxResult<ContentSandboxTile>.Fail(info.Failure);
                }

                return await TileCoreAsync(
                    state.Format,
                    info.Value.Width,
                    info.Value.Height,
                    x,
                    y,
                    width,
                    height,
                    async (grant, region, call) =>
                    {
                        var response = await _client.ReadImageTileAsync(
                            new ContentSandboxServiceReadImageTileRequest
                            {
                                Meta = NewMeta(),
                                SessionId = SandboxRecords.ToWireId(_sessionId),
                                ImageId = SandboxRecords.ToWireId(imageId),
                                Region = region,
                                Grant = grant,
                            },
                            call).ConfigureAwait(false);
                        return response.OutcomeCase == ContentSandboxServiceReadImageTileResponse.OutcomeOneofCase.Value
                            ? (response.Value.Buffer, null)
                            : (null, response.Error);
                    },
                    token).ConfigureAwait(false);
            },
            cancellationToken).ConfigureAwait(false);

    /// <summary>Closes an opened image. Closing an unknown image is a typed refusal.</summary>
    /// <param name="imageId">The identifier returned by <see cref="OpenImageAsync"/>.</param>
    /// <param name="cancellationToken">Cancels the call, and with it the invocation.</param>
    public async ValueTask<ContentSandboxResult<bool>> CloseImageAsync(Guid imageId, CancellationToken cancellationToken = default) =>
        await RunAsync(
            async token =>
            {
                if (!_images.Remove(imageId))
                {
                    return ContentSandboxResult<bool>.Fail("state.not_found");
                }

                var response = await _client.CloseImageAsync(
                    new ContentSandboxServiceCloseImageRequest
                    {
                        Meta = NewMeta(),
                        SessionId = SandboxRecords.ToWireId(_sessionId),
                        ImageId = SandboxRecords.ToWireId(imageId),
                    },
                    CallOptions(token)).ConfigureAwait(false);
                return response.OutcomeCase == ContentSandboxServiceCloseImageResponse.OutcomeOneofCase.Value
                    ? ContentSandboxResult<bool>.Ok(true)
                    : Failed<bool>(response.Error);
            },
            cancellationToken).ConfigureAwait(false);

    /// <summary>Opens the input as a PDF document. The document keeps the identifier the parent mints here.</summary>
    /// <param name="cancellationToken">Cancels the call, and with it the invocation.</param>
    public async ValueTask<ContentSandboxResult<Guid>> OpenPdfAsync(CancellationToken cancellationToken = default) =>
        await RunAsync(
            async token =>
            {
                var documentId = Guid.NewGuid();
                var response = await _client.OpenPdfAsync(
                    new ContentSandboxServiceOpenPdfRequest
                    {
                        Meta = NewMeta(),
                        SessionId = SandboxRecords.ToWireId(_sessionId),
                        DocumentId = SandboxRecords.ToWireId(documentId),
                    },
                    CallOptions(token)).ConfigureAwait(false);
                if (response.OutcomeCase != ContentSandboxServiceOpenPdfResponse.OutcomeOneofCase.Value)
                {
                    return Failed<Guid>(response.Error);
                }

                if (!SandboxRecords.TryReadId(response.Value.DocumentId, out var echoed) || echoed != documentId || !response.Value.HasPageCount
                    || response.Value.PageCount > _options.Limits.MaxItems)
                {
                    return await EndedBecauseAsync<Guid>("resource.parser_failed").ConfigureAwait(false);
                }

                _documents[documentId] = response.Value.PageCount;
                return ContentSandboxResult<Guid>.Ok(documentId);
            },
            cancellationToken).ConfigureAwait(false);

    /// <summary>Reads the geometry of one page of an opened document.</summary>
    /// <param name="documentId">The identifier returned by <see cref="OpenPdfAsync"/>.</param>
    /// <param name="pageIndex">The zero-based page.</param>
    /// <param name="cancellationToken">Cancels the call, and with it the invocation.</param>
    public async ValueTask<ContentSandboxResult<SandboxPdfPage>> GetPdfPageAsync(Guid documentId, uint pageIndex, CancellationToken cancellationToken = default) =>
        await RunAsync(
            async token =>
            {
                if (!_documents.TryGetValue(documentId, out var pages) || pageIndex >= pages)
                {
                    return ContentSandboxResult<SandboxPdfPage>.Fail("state.not_found");
                }

                var response = await _client.GetPdfPageAsync(
                    new ContentSandboxServiceGetPdfPageRequest
                    {
                        Meta = NewMeta(),
                        SessionId = SandboxRecords.ToWireId(_sessionId),
                        DocumentId = SandboxRecords.ToWireId(documentId),
                        PageIndex = pageIndex,
                    },
                    CallOptions(token)).ConfigureAwait(false);
                if (response.OutcomeCase != ContentSandboxServiceGetPdfPageResponse.OutcomeOneofCase.Value)
                {
                    return Failed<SandboxPdfPage>(response.Error);
                }

                var page = response.Value.Page;
                if (!SandboxProfileCheck.IsValid(page) || page.PageIndex != pageIndex)
                {
                    return await EndedBecauseAsync<SandboxPdfPage>("resource.parser_failed").ConfigureAwait(false);
                }

                return ContentSandboxResult<SandboxPdfPage>.Ok(page);
            },
            cancellationToken).ConfigureAwait(false);

    /// <summary>Extracts a bounded chunk of page text with UTF-16 positions; <c>start</c> is 0 or the next position a previous chunk returned.</summary>
    /// <param name="documentId">The identifier returned by <see cref="OpenPdfAsync"/>.</param>
    /// <param name="pageIndex">The zero-based page.</param>
    /// <param name="start">The UTF-16 position to start at.</param>
    /// <param name="cancellationToken">Cancels the call, and with it the invocation.</param>
    public async ValueTask<ContentSandboxResult<SandboxPdfText>> ExtractPdfTextAsync(Guid documentId, uint pageIndex, uint start, CancellationToken cancellationToken = default) =>
        await RunAsync(
            async token =>
            {
                if (!_documents.TryGetValue(documentId, out var pages) || pageIndex >= pages)
                {
                    return ContentSandboxResult<SandboxPdfText>.Fail("state.not_found");
                }

                var response = await _client.ExtractPdfTextAsync(
                    new ContentSandboxServiceExtractPdfTextRequest
                    {
                        Meta = NewMeta(),
                        SessionId = SandboxRecords.ToWireId(_sessionId),
                        DocumentId = SandboxRecords.ToWireId(documentId),
                        PageIndex = pageIndex,
                        Start = start,
                    },
                    CallOptions(token)).ConfigureAwait(false);
                if (response.OutcomeCase != ContentSandboxServiceExtractPdfTextResponse.OutcomeOneofCase.Value)
                {
                    return Failed<SandboxPdfText>(response.Error);
                }

                var text = response.Value.Text;
                if (!SandboxProfileCheck.IsValid(response) || text.PageIndex != pageIndex || text.Start != start
                    || (uint)text.Boxes.Count > _options.Limits.MaxItems || (text.HasNext && text.Next <= start))
                {
                    return await EndedBecauseAsync<SandboxPdfText>("resource.parser_failed").ConfigureAwait(false);
                }

                return ContentSandboxResult<SandboxPdfText>.Ok(text);
            },
            cancellationToken).ConfigureAwait(false);

    /// <summary>Renders one tile of a page through a brokered output slot, with the same checks as <see cref="ReadImageTileAsync"/>.</summary>
    /// <param name="documentId">The identifier returned by <see cref="OpenPdfAsync"/>.</param>
    /// <param name="page">The page geometry exactly as <see cref="GetPdfPageAsync"/> returned it.</param>
    /// <param name="fullWidth">The full rendered width in pixels.</param>
    /// <param name="fullHeight">The full rendered height in pixels.</param>
    /// <param name="x">The tile origin.</param>
    /// <param name="y">The tile origin.</param>
    /// <param name="width">The tile width in pixels, 1 through 2048.</param>
    /// <param name="height">The tile height in pixels, 1 through 2048.</param>
    /// <param name="cancellationToken">Cancels the call, and with it the invocation.</param>
    public async ValueTask<ContentSandboxResult<ContentSandboxTile>> RenderPdfTileAsync(
        Guid documentId,
        SandboxPdfPage page,
        uint fullWidth,
        uint fullHeight,
        uint x,
        uint y,
        uint width,
        uint height,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(page);
        return await RunAsync(
            token =>
            {
                if (!_documents.TryGetValue(documentId, out var pages) || !page.HasPageIndex || page.PageIndex >= pages || !SandboxProfileCheck.IsValid(page))
                {
                    return ValueTask.FromResult(ContentSandboxResult<ContentSandboxTile>.Fail("state.not_found"));
                }

                return TileCoreAsync(
                    1,
                    fullWidth,
                    fullHeight,
                    x,
                    y,
                    width,
                    height,
                    async (grant, region, call) =>
                    {
                        var response = await _client.RenderPdfTileAsync(
                            new ContentSandboxServiceRenderPdfTileRequest
                            {
                                Meta = NewMeta(),
                                SessionId = SandboxRecords.ToWireId(_sessionId),
                                DocumentId = SandboxRecords.ToWireId(documentId),
                                Page = page,
                                Region = region,
                                Grant = grant,
                                FullWidth = fullWidth,
                                FullHeight = fullHeight,
                            },
                            call).ConfigureAwait(false);
                        return response.OutcomeCase == ContentSandboxServiceRenderPdfTileResponse.OutcomeOneofCase.Value
                            ? (response.Value.Buffer, null)
                            : (null, response.Error);
                    },
                    token);
            },
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Closes an opened document. Closing an unknown document is a typed refusal.</summary>
    /// <param name="documentId">The identifier returned by <see cref="OpenPdfAsync"/>.</param>
    /// <param name="cancellationToken">Cancels the call, and with it the invocation.</param>
    public async ValueTask<ContentSandboxResult<bool>> ClosePdfAsync(Guid documentId, CancellationToken cancellationToken = default) =>
        await RunAsync(
            async token =>
            {
                if (!_documents.Remove(documentId))
                {
                    return ContentSandboxResult<bool>.Fail("state.not_found");
                }

                var response = await _client.ClosePdfAsync(
                    new ContentSandboxServiceClosePdfRequest
                    {
                        Meta = NewMeta(),
                        SessionId = SandboxRecords.ToWireId(_sessionId),
                        DocumentId = SandboxRecords.ToWireId(documentId),
                    },
                    CallOptions(token)).ConfigureAwait(false);
                return response.OutcomeCase == ContentSandboxServiceClosePdfResponse.OutcomeOneofCase.Value
                    ? ContentSandboxResult<bool>.Ok(true)
                    : Failed<bool>(response.Error);
            },
            cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Cancels the invocation: every grant is withdrawn, in-flight calls are abandoned and the helper is asked to stop through the reserved
    /// cancellation control slot, which works even when the data lane is full. A helper that does not stop within five seconds is terminated.
    /// </summary>
    /// <returns>True when the helper acknowledged the cancellation before it was terminated.</returns>
    public async ValueTask<bool> CancelAsync()
    {
        if (IsEnded)
        {
            return false;
        }

        _session?.Cancel();
        var acknowledged = false;
        try
        {
            using var grace = new CancellationTokenSource(CancelGrace);
            var response = await _client.CancelSessionAsync(
                new ContentSandboxServiceCancelSessionRequest
                {
                    Meta = NewMeta(),
                    SessionId = SandboxRecords.ToWireId(_sessionId),
                },
                new CallOptions(deadline: DateTime.UtcNow + CancelGrace, cancellationToken: grace.Token)).ConfigureAwait(false);
            acknowledged = response.OutcomeCase == ContentSandboxServiceCancelSessionResponse.OutcomeOneofCase.Value;
        }
        catch (RpcException)
        {
            acknowledged = false;
        }
        catch (OperationCanceledException)
        {
            acknowledged = false;
        }

        await _lifetime.CancelAsync().ConfigureAwait(false);
        if (!acknowledged)
        {
            Terminate();
        }

        return acknowledged;
    }

    /// <summary>Closes the session: the helper releases everything and exits; the parent waits for it a bounded time and then terminates what remains.</summary>
    public async ValueTask CloseAsync()
    {
        if (IsEnded)
        {
            return;
        }

        // The helper ends its own streams on the way out; that is the orderly end, not a loss to terminate over.
        _ = Interlocked.Exchange(ref _closing, 1);

        try
        {
            _ = await _client.CloseSessionAsync(
                new ContentSandboxServiceCloseSessionRequest
                {
                    Meta = NewMeta(),
                    SessionId = SandboxRecords.ToWireId(_sessionId),
                },
                new CallOptions(deadline: DateTime.UtcNow + CancelGrace)).ConfigureAwait(false);
        }
        catch (RpcException)
        {
            // The helper is gone or unresponsive; it is terminated below.
        }

        _session?.Close();
        try
        {
            _ = await _helper.Exited.WaitAsync(CancelGrace).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            Terminate();
        }
    }

    /// <summary>Completes with the exit code when the helper process has ended, however it ended.</summary>
    /// <param name="cancellationToken">Stops waiting; the helper is not affected.</param>
    public async ValueTask<int> WaitForExitAsync(CancellationToken cancellationToken = default) =>
        await _helper.Exited.WaitAsync(cancellationToken).ConfigureAwait(false);

    /// <summary>Terminates the helper process tree if it is still running, releases every mapping and stream once, and ends the launch.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Terminate();
        _ = _stopSupervision.TrySetResult();
        await _lifetime.CancelAsync().ConfigureAwait(false);
        try
        {
            await _supervision.WaitAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // Supervision only observes; the helper below is already gone or unreachable.
        }

        _session?.Dispose();
        _registry.Dispose();
        await _channel.DisposeAsync().ConfigureAwait(false);
        await _bootstrapServer.DisposeAsync().ConfigureAwait(false);
        await _registration.DisposeAsync().ConfigureAwait(false);
        await _launch.DisposeAsync().ConfigureAwait(false);
        await _helper.DisposeAsync().ConfigureAwait(false);
        _operations.Dispose();
        _lifetime.Dispose();
    }

    private static async Task WaitRegisteredAsync(LocalRpcRegistration registration, IProvisionedHelper helper, CancellationToken cancellationToken)
    {
        while (registration.State != LocalRpcRegistrationState.Registered)
        {
            if (registration.State == LocalRpcRegistrationState.Ended || helper.Exited.IsCompleted)
            {
                throw new ContentSandboxLaunchException(ReasonForStartFailure(helper), "The helper did not register.");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(15), cancellationToken).ConfigureAwait(false);
        }
    }

    private static string Describe(Exception exception, IProvisionedHelper? helper)
    {
        var inner = exception.InnerException;
        var exit = helper is { Exited.IsCompletedSuccessfully: true } ? " exit=" + helper.Exited.Result : string.Empty;
        return exception.GetType().Name + ": " + exception.Message + (inner is null ? string.Empty : " / " + inner.GetType().Name + ": " + inner.Message) + exit + (helper is null ? string.Empty : " output=" + helper.DiagnosticTail.ReplaceLineEndings(" "));
    }

    private static string ReasonForStartFailure(IProvisionedHelper? helper)
    {
        if (helper is { Exited.IsCompleted: true } && helper.Exited.Status == TaskStatus.RanToCompletion
            && helper.Exited.Result == ContentSandboxContract.ExitIsolationUnavailable)
        {
            return "security.isolation_unavailable";
        }

        return "resource.unavailable";
    }

    private static async Task DisposePartialAsync(
        IProvisionedHelper? helper,
        LocalRpcClientChannel? channel,
        LocalRpcServer? server,
        LocalRpcRegistration? registration,
        LocalRpcLaunch? launch)
    {
        helper?.Terminate();
        if (channel is not null)
        {
            await channel.DisposeAsync().ConfigureAwait(false);
        }

        if (server is not null)
        {
            await server.DisposeAsync().ConfigureAwait(false);
        }

        if (registration is not null)
        {
            await registration.DisposeAsync().ConfigureAwait(false);
        }

        if (launch is not null)
        {
            await launch.DisposeAsync().ConfigureAwait(false);
        }

        if (helper is not null)
        {
            await helper.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async ValueTask<ContentSandboxResult<bool>> OpenSessionAsync(Guid inputId, ulong inputLength, byte[] inputDigest, CancellationToken cancellationToken)
    {
        var limits = _options.Limits;
        var request = new ContentSandboxServiceOpenSessionRequest
        {
            Meta = NewMeta(),
            Input = new SandboxInput
            {
                InvocationId = SandboxRecords.ToWireId(_invocationId),
                Generation = _generation,
                InputId = SandboxRecords.ToWireId(inputId),
                Length = inputLength,
                Sha256 = Convert.ToHexStringLower(inputDigest),
            },
            Limits = limits.ToWire(),
        };
        ContentSandboxServiceOpenSessionResponse response;
        try
        {
            response = await _client.OpenSessionAsync(request, new CallOptions(deadline: DateTime.UtcNow + MaxCall, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        catch (RpcException)
        {
            Terminate();
            return ContentSandboxResult<bool>.Fail(ReasonForStartFailure(_helper));
        }

        if (response.OutcomeCase != ContentSandboxServiceOpenSessionResponse.OutcomeOneofCase.Value)
        {
            Terminate();
            return Failed<bool>(response.Error);
        }

        var session = response.Value.Session;
        if (!SandboxRecords.TryReadId(session?.SessionId, out var sessionId)
            || !SandboxRecords.TryReadId(session!.InvocationId, out var invocation) || invocation != _invocationId
            || !SandboxRecords.TryReadId(session.LeaseId, out var lease) || lease != _leaseId
            || !session.HasGeneration || session.Generation != _generation
            || session.Input is null || !SandboxRecords.TryReadId(session.Input.InputId, out var echoedInput) || echoedInput != inputId
            || !ContentSandboxLimits.TryFromWire(session.Limits, out var echoedLimits) || echoedLimits != limits)
        {
            Terminate();
            return ContentSandboxResult<bool>.Fail("resource.parser_failed");
        }

        _sessionId = sessionId;
        var created = _registry.CreateSession(new LocalRpcBrokerSessionOptions
        {
            InvocationId = _invocationId,
            LeaseId = _leaseId,
            Generation = _generation,
            Slots = _helper.SlotMappings,
            PairGone = _registration.Ended,
            PairLives = () => !IsEnded && _registration.State == LocalRpcRegistrationState.Registered,
            Ended = OnSessionEnded,
        });
        if (!created.IsSuccess)
        {
            Terminate();
            return ContentSandboxResult<bool>.Fail("capacity.busy");
        }

        _session = created.Value;
        return ContentSandboxResult<bool>.Ok(true);
    }

    private async ValueTask<ContentSandboxResult<SandboxImageInfo>> ImageInfoCoreAsync(Guid imageId, CancellationToken token)
    {
        if (!_images.TryGetValue(imageId, out var state))
        {
            return ContentSandboxResult<SandboxImageInfo>.Fail("state.not_found");
        }

        if (state.Info is { } cached)
        {
            return ContentSandboxResult<SandboxImageInfo>.Ok(cached);
        }

        var response = await _client.GetImageInfoAsync(
            new ContentSandboxServiceGetImageInfoRequest
            {
                Meta = NewMeta(),
                SessionId = SandboxRecords.ToWireId(_sessionId),
                ImageId = SandboxRecords.ToWireId(imageId),
            },
            CallOptions(token)).ConfigureAwait(false);
        if (response.OutcomeCase != ContentSandboxServiceGetImageInfoResponse.OutcomeOneofCase.Value)
        {
            return Failed<SandboxImageInfo>(response.Error);
        }

        var info = response.Value.Info;
        var items = (long)info.Channels.Count + info.Tags.Count + info.Warnings.Count;
        if (!SandboxProfileCheck.IsValid(info) || info.Width > _options.Limits.MaxWidth || info.Height > _options.Limits.MaxHeight
            || items > _options.Limits.MaxItems)
        {
            return await EndedBecauseAsync<SandboxImageInfo>("resource.parser_failed").ConfigureAwait(false);
        }

        _images[imageId] = state with { Info = info };
        return ContentSandboxResult<SandboxImageInfo>.Ok(info);
    }

    private async ValueTask<ContentSandboxResult<ContentSandboxTile>> TileCoreAsync(
        uint format,
        uint fullWidth,
        uint fullHeight,
        uint x,
        uint y,
        uint width,
        uint height,
        Func<SandboxSlotGrant, SandboxRegion, CallOptions, Task<(SandboxBufferDescriptor? Buffer, ArcError? Error)>> request,
        CancellationToken token)
    {
        var geometry = new TileGeometry(format, fullWidth, fullHeight, x, y, width, height);
        var layout = geometry.Layout();
        var session = _session;
        if (session is null || layout is null || fullWidth == 0 || fullHeight == 0 || fullWidth > _options.Limits.MaxWidth
            || fullHeight > _options.Limits.MaxHeight || width > 2048 || height > 2048
            || (ulong)x + width > fullWidth || (ulong)y + height > fullHeight)
        {
            return ContentSandboxResult<ContentSandboxTile>.Fail("validation.invalid_request");
        }

        var rowStride = layout.RowBytes;
        var capacity = layout.Rows * rowStride;
        var region = new SandboxRegion { X = x, Y = y, Width = width, Height = height, FirstSample = 0, SampleCount = 0, RowStride = rowStride };
        if (!SandboxProfileCheck.IsValid(region))
        {
            return ContentSandboxResult<ContentSandboxTile>.Fail("validation.invalid_request");
        }

        var slot = FreeSlot(session, capacity);
        if (slot is null)
        {
            return ContentSandboxResult<ContentSandboxTile>.Fail("capacity.busy");
        }

        var granted = session.Grant(slot.Value, capacity);
        if (!granted.IsSuccess)
        {
            return ContentSandboxResult<ContentSandboxTile>.Fail(granted.Refusal == LocalRpcBrokerRefusal.CapacityExceeded ? "validation.invalid_request" : "state.invalid_transition");
        }

        var grant = granted.Value ?? throw new InvalidOperationException("A granted slot carries its grant.");
        var wireGrant = SandboxRecords.ToWire(grant);
        var grantResponse = await _client.GrantSlotAsync(
            new ContentSandboxServiceGrantSlotRequest
            {
                Meta = NewMeta(),
                SessionId = SandboxRecords.ToWireId(_sessionId),
                Grant = wireGrant,
            },
            CallOptions(token)).ConfigureAwait(false);
        if (grantResponse.OutcomeCase != ContentSandboxServiceGrantSlotResponse.OutcomeOneofCase.Value)
        {
            return await EndedBecauseAsync<ContentSandboxTile>("state.stale_fence").ConfigureAwait(false);
        }

        var (descriptor, error) = await request(wireGrant, region, CallOptions(token)).ConfigureAwait(false);
        if (descriptor is null)
        {
            return await EndedWithAsync<ContentSandboxTile>(error).ConfigureAwait(false);
        }

        if (!SandboxRecords.TryReadSeal(descriptor, out var seal, out var echoed)
            || !SandboxProfileCheck.IsValid(descriptor, wireGrant, region)
            || echoed != geometry)
        {
            return await EndedBecauseAsync<ContentSandboxTile>("resource.integrity_failed").ConfigureAwait(false);
        }

        var refusal = session.Seal(seal, layout);
        if (refusal != LocalRpcBrokerRefusal.None)
        {
            return await EndedBecauseAsync<ContentSandboxTile>("resource.integrity_failed").ConfigureAwait(false);
        }

        var copy = await session.CopyAsync(grant.SlotId, grant.Sequence, token).ConfigureAwait(false);
        var buffer = copy.Value;
        if (!copy.IsSuccess || buffer is null)
        {
            return await EndedBecauseAsync<ContentSandboxTile>("resource.integrity_failed").ConfigureAwait(false);
        }

        var acknowledged = session.Acknowledge(grant.SlotId, grant.Sequence);
        var ack = acknowledged.Value;
        if (!acknowledged.IsSuccess || ack is null)
        {
            buffer.Dispose();
            return await EndedBecauseAsync<ContentSandboxTile>("resource.integrity_failed").ConfigureAwait(false);
        }

        var ackResponse = await _client.AckBufferAsync(
            new ContentSandboxServiceAckBufferRequest
            {
                Meta = NewMeta(),
                SessionId = SandboxRecords.ToWireId(_sessionId),
                Ack = SandboxRecords.ToWire(ack),
            },
            CallOptions(token)).ConfigureAwait(false);
        if (ackResponse.OutcomeCase != ContentSandboxServiceAckBufferResponse.OutcomeOneofCase.Value)
        {
            buffer.Dispose();
            return await EndedBecauseAsync<ContentSandboxTile>("state.stale_fence").ConfigureAwait(false);
        }

#pragma warning disable CA2000 // Ownership of the tile passes to the caller, who disposes it.
        return ContentSandboxResult<ContentSandboxTile>.Ok(new ContentSandboxTile(buffer, format, fullWidth, fullHeight, x, y, width, height, rowStride));
#pragma warning restore CA2000
    }

    private static uint? FreeSlot(LocalRpcBrokerSession session, ulong capacity)
    {
        var snapshot = session.GetSnapshot();
        for (var index = 0; index < snapshot.Slots.Count; index++)
        {
            if (snapshot.Slots[index] == LocalRpcSlotState.Free)
            {
                _ = capacity;
                return (uint)index;
            }
        }

        return null;
    }

    /// <summary>
    /// Runs one operation: operations of an invocation run one at a time, a failure of the helper or of the transport ends the
    /// invocation with a typed reason, and the caller's cancellation cancels the invocation.
    /// </summary>
    private async ValueTask<ContentSandboxResult<T>> RunAsync<T>(Func<CancellationToken, ValueTask<ContentSandboxResult<T>>> operation, CancellationToken cancellationToken)
    {
        if (IsEnded || _session is null)
        {
            return ContentSandboxResult<T>.Fail("resource.parser_failed");
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        try
        {
            await _operations.WaitAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ContentSandboxResult<T>.Fail("resource.parser_failed");
        }

        try
        {
            return await operation(linked.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (cancellationToken.IsCancellationRequested && exception is RpcException or OperationCanceledException)
        {
            _ = await CancelAsync().ConfigureAwait(false);
            throw new OperationCanceledException(cancellationToken);
        }
        catch (RpcException exception)
        {
            return FailedTransport<T>(exception);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _ = await CancelAsync().ConfigureAwait(false);
            throw;
        }
        catch (OperationCanceledException)
        {
            return ContentSandboxResult<T>.Fail("resource.parser_failed");
        }
        finally
        {
            _ = _operations.Release();
        }
    }

    private ContentSandboxResult<T> FailedTransport<T>(RpcException exception)
    {
        if (LocalRpcRefusal.TryRead(exception, out _))
        {
            return ContentSandboxResult<T>.Fail("capacity.busy");
        }

        // Anything else may have reached the helper: it crashed, hung past its deadline, lost its stream or misbehaved. The invocation
        // ends and the owner may reopen the immutable input under a new one; no product state was committed.
        Terminate();
        return ContentSandboxResult<T>.Fail("resource.parser_failed");
    }

    private static ContentSandboxResult<T> Failed<T>(ArcError? error) =>
        error is null ? ContentSandboxResult<T>.Fail("resource.parser_failed") : ContentSandboxResult<T>.Fail(TypedFailure.FromWire(error));

    private async ValueTask<ContentSandboxResult<T>> EndedWithAsync<T>(ArcError? error)
    {
        await Task.CompletedTask.ConfigureAwait(false);
        Terminate();
        return Failed<T>(error);
    }

    private async ValueTask<ContentSandboxResult<T>> EndedBecauseAsync<T>(string code)
    {
        await Task.CompletedTask.ConfigureAwait(false);
        Terminate();
        return ContentSandboxResult<T>.Fail(code);
    }

    private void Terminate()
    {
        if (Interlocked.Exchange(ref _terminated, 1) == 0)
        {
            _helper.Terminate();
            try
            {
                _lifetime.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // Disposal already ran.
            }
        }
    }

    private void OnSessionEnded(LocalRpcBrokerEnd end)
    {
        if (end.Reason is not (LocalRpcBrokerEndReason.Closed or LocalRpcBrokerEndReason.RegistryDisposed))
        {
            Terminate();
        }
    }

    private async Task Supervise()
    {
        var exited = _helper.Exited;
        var registrationEnded = Task.Delay(Timeout.Infinite, _registration.Ended);
        var renewal = RenewAsync();
        var first = await Task.WhenAny(exited, registrationEnded, _renewalLost.Task, _stopSupervision.Task).ConfigureAwait(false);
        if (first != _stopSupervision.Task && Volatile.Read(ref _closing) == 0)
        {
            Terminate();
        }

        _ = renewal;
    }

    private async Task RenewAsync()
    {
        using var timer = new PeriodicTimer(RenewInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(_lifetime.Token).ConfigureAwait(false))
            {
                if (_session is not { } session)
                {
                    continue;
                }

                if (session.Renew() != LocalRpcBrokerRefusal.None)
                {
                    _ = _renewalLost.TrySetResult();
                    return;
                }

                var response = await _client.RenewSessionAsync(
                    new ContentSandboxServiceRenewSessionRequest { Meta = NewMeta(), SessionId = SandboxRecords.ToWireId(_sessionId) },
                    new CallOptions(deadline: DateTime.UtcNow + CancelGrace, cancellationToken: _lifetime.Token)).ConfigureAwait(false);
                if (response.OutcomeCase != ContentSandboxServiceRenewSessionResponse.OutcomeOneofCase.Value)
                {
                    _ = _renewalLost.TrySetResult();
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // The invocation ended.
        }
        catch (RpcException)
        {
            // The helper no longer answers; supervision ends it.
            _ = _renewalLost.TrySetResult();
        }
    }

    private CallOptions CallOptions(CancellationToken token) =>
        new(deadline: DateTime.UtcNow + Min(TimeSpan.FromMilliseconds(_options.Limits.TimeoutMs) + CallMargin, MaxCall), cancellationToken: token);

    private static TimeSpan Min(TimeSpan left, TimeSpan right) => left < right ? left : right;

    private static RequestMeta NewMeta() => new()
    {
        CommandId = SandboxRecords.ToWireId(Guid.NewGuid()),
        CorrelationId = SandboxRecords.ToWireId(Guid.NewGuid()),
    };

    private sealed record ImageState(uint Format, SandboxImageInfo? Info);
}
