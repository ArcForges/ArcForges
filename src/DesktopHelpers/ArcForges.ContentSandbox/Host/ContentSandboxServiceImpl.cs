// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Sandbox.Shapes;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using ArcForges.Foundation.Errors;
using ArcForges.LocalRpc;
using Grpc.Core;
using SandboxProfileCheck = ArcForges.Contracts.LocalRpc.Sandbox.SandboxProfile;
using Shape = ArcForges.Contracts.LocalRpc.Sandbox.Shapes.ContractShapeValidation;

namespace ArcForges.ContentSandbox.Host;

/// <summary>
/// The helper's side of the generated sandbox contract. It holds exactly one invocation-scoped session whose identity, input and budget the
/// launch fixed; it chooses parsers only from the signed composition of the launch; it fills only the slot grants the parent made; and
/// every result is checked against the same shape rules the parent applies again. A parser that fails, overruns its deadline or is cancelled
/// ends the invocation: nothing it produced is kept, and nothing it throws is sent.
/// </summary>
[SuppressMessage("Maintainability", "CA1506", Justification = "The service is the one owner of the helper session and implements the fifteen generated methods.")]
internal sealed class ContentSandboxServiceImpl : ContentSandboxService.ContentSandboxServiceBase, IDisposable
{
    private const int MaxOpenObjects = 8;
    private const int MaxPdfTextBytes = 60 * 1024;
    private const int RememberedRenewals = 16;
    private static readonly TimeSpan SessionLease = TimeSpan.FromSeconds(30);

    private readonly ContentSandboxLaunchFrame _frame;
    private readonly HelperResources _resources;
    private readonly IContentParserProfile? _profile;
    private readonly TimeProvider _clock;
    private readonly Action<int> _requestExit;
    private readonly object _gate = new();
    private readonly string _inputDigestHex;
    private SessionState? _session;
    private int _disposed;

    internal ContentSandboxServiceImpl(
        ContentSandboxLaunchFrame frame,
        HelperResources resources,
        IContentParserProfile? profile,
        TimeProvider clock,
        Action<int> requestExit)
    {
        _frame = frame;
        _resources = resources;
        _profile = profile;
        _clock = clock;
        _requestExit = requestExit;
        _inputDigestHex = Convert.ToHexStringLower(frame.InputDigest);
    }

    /// <summary>The full name of the service this implementation serves, for explicit registration and the control declarations.</summary>
    internal static string ServiceName => ContentSandboxContract.ServiceName;

    /// <summary>True when the session lease has passed without a renewal.</summary>
    internal bool IsExpired
    {
        get
        {
            lock (_gate)
            {
                return _session is { } session && session.LeaseEnds <= _clock.GetTimestamp();
            }
        }
    }

    /// <inheritdoc />
    public override async Task<ContentSandboxServiceOpenSessionResponse> OpenSession(ContentSandboxServiceOpenSessionRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new ContentSandboxServiceOpenSessionResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request)
            || !SandboxRecords.TryReadId(request.Input.InvocationId, out var invocation) || invocation != _frame.InvocationId
            || request.Input.Generation != _frame.Generation
            || !SandboxRecords.TryReadId(request.Input.InputId, out var inputId) || inputId != _frame.InputId
            || request.Input.Length != _frame.InputLength
            || !string.Equals(request.Input.Sha256, _inputDigestHex, StringComparison.Ordinal)
            || !ContentSandboxLimits.TryFromWire(request.Limits, out var limits) || !limits.FitsWithin(_frame.Limits))
        {
            response.Error = Failure("validation.invalid_request");
            return response;
        }

        lock (_gate)
        {
            if (_session is not null)
            {
                response.Error = Failure("state.invalid_transition");
                return response;
            }

            _session = new SessionState(); // reserve: a second open sees it
        }

        if (_profile is null)
        {
            Release();
            response.Error = Failure("resource.unavailable");
            return response;
        }

        var verified = await LocalRpcBrokerChild.VerifyInputAsync(
            _resources.Input,
            _frame.InputLength,
            LocalRpcDigest.FromBytes(_frame.InputDigest),
            256 * 1024,
            context.CancellationToken).ConfigureAwait(false);
        if (verified != LocalRpcBrokerRefusal.None)
        {
            Release();
            response.Error = Failure("resource.integrity_failed");
            return response;
        }

        var capacities = _resources.Slots.Select(slot => slot.Capacity).ToArray();
        for (var index = 0; index < capacities.Length; index++)
        {
            if ((ulong)capacities[index] != _frame.SlotCapacities[index])
            {
                Release();
                response.Error = Failure("resource.integrity_failed");
                return response;
            }
        }

        var broker = new LocalRpcBrokerChild(_frame.InvocationId, _frame.LeaseId, _frame.Generation, capacities);
        var session = new SessionState
        {
            SessionId = Guid.NewGuid(),
            Broker = broker,
            Limits = limits,
            LeaseEnds = _clock.GetTimestamp() + Ticks(SessionLease),
        };
        lock (_gate)
        {
            _session = session;
        }

        response.Value = new ContentSandboxServiceOpenSessionValue
        {
            Session = new SandboxSession
            {
                SessionId = SandboxRecords.ToWireId(session.SessionId),
                InvocationId = SandboxRecords.ToWireId(_frame.InvocationId),
                LeaseId = SandboxRecords.ToWireId(_frame.LeaseId),
                Generation = _frame.Generation,
                ExpiresAt = SandboxRecords.ToInstant(_clock.GetUtcNow() + SessionLease),
                Input = request.Input.Clone(),
                Limits = limits.ToWire(),
            },
        };
        return response;
    }

    /// <inheritdoc />
    public override Task<ContentSandboxServiceRenewSessionResponse> RenewSession(ContentSandboxServiceRenewSessionRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new ContentSandboxServiceRenewSessionResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetSession(request.SessionId, out var session))
        {
            response.Error = Failure(Shape.IsValid(request) ? "state.not_found" : "validation.invalid_request");
            return Task.FromResult(response);
        }

        DateTimeOffset expiresAt;
        lock (_gate)
        {
            var now = _clock.GetTimestamp();
            if (session.LeaseEnds <= now || session.Closed)
            {
                response.Error = Failure("perm.lease_expired");
                return Task.FromResult(response);
            }

            var command = request.Meta.CommandId?.Value.ToByteArray() ?? [];
            var key = Convert.ToHexStringLower(command);
            if (command.Length == 16 && session.Renewals.TryGetValue(key, out var recorded))
            {
                expiresAt = recorded;
            }
            else
            {
                session.LeaseEnds = now + Ticks(SessionLease);
                expiresAt = _clock.GetUtcNow() + SessionLease;
                if (command.Length == 16)
                {
                    if (session.Renewals.Count >= RememberedRenewals)
                    {
                        session.Renewals.Remove(session.RenewalOrder.Dequeue());
                    }

                    session.Renewals[key] = expiresAt;
                    session.RenewalOrder.Enqueue(key);
                }
            }
        }

        response.Value = new ContentSandboxServiceRenewSessionValue { ExpiresAt = SandboxRecords.ToInstant(expiresAt) };
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<ContentSandboxServiceGrantSlotResponse> GrantSlot(ContentSandboxServiceGrantSlotRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new ContentSandboxServiceGrantSlotResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetLiveSession(request.SessionId, out var session)
            || !SandboxRecords.TryReadGrant(request.Grant, out var grant))
        {
            response.Error = Failure("validation.invalid_request");
            return Task.FromResult(response);
        }

        var accepted = session.Broker!.Accept(grant);
        if (!accepted.IsSuccess)
        {
            response.Error = Failure(Reason(accepted.Refusal));
            return Task.FromResult(response);
        }

        lock (_gate)
        {
            session.Grants[grant.SlotId] = grant;
        }

        response.Value = new ContentSandboxServiceGrantSlotValue { Receipt = ReceiptOf(request.Meta) };
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override Task<ContentSandboxServiceAckBufferResponse> AckBuffer(ContentSandboxServiceAckBufferRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new ContentSandboxServiceAckBufferResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetLiveSession(request.SessionId, out var session) || !SandboxRecords.TryReadAck(request.Ack, out var ack))
        {
            response.Error = Failure("validation.invalid_request");
            return Task.FromResult(response);
        }

        var refusal = session.Broker!.Acknowledge(ack);
        if (refusal != LocalRpcBrokerRefusal.None)
        {
            response.Error = Failure(Reason(refusal));
            return Task.FromResult(response);
        }

        lock (_gate)
        {
            _ = session.Grants.Remove(ack.SlotId);
        }

        response.Value = new ContentSandboxServiceAckBufferValue { Receipt = ReceiptOf(request.Meta) };
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task<ContentSandboxServiceOpenImageResponse> OpenImage(ContentSandboxServiceOpenImageRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new ContentSandboxServiceOpenImageResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetLiveSession(request.SessionId, out var session)
            || !SandboxRecords.TryReadId(request.ImageId, out var imageId)
            || request.OutputFormat is not (1 or 2) || request.Subimage > 64 || request.Mip > 64)
        {
            response.Error = Failure("validation.invalid_request");
            return response;
        }

        ImageState? existing;
        lock (_gate)
        {
            _ = session.Images.TryGetValue(imageId, out existing);
            if (existing is null && session.Images.Count >= MaxOpenObjects)
            {
                response.Error = Failure("capacity.busy");
                return response;
            }
        }

        if (existing is not null)
        {
            response.Error = existing.Matches(request.Subimage, request.Mip, request.OutputFormat) ? null : Failure("conflict.duplicate_identifier");
            if (response.Error is null)
            {
                response.Value = new ContentSandboxServiceOpenImageValue { ImageId = SandboxRecords.ToWireId(imageId) };
            }

            return response;
        }

        var parser = _profile?.CreateImageParser();
        if (parser is null)
        {
            response.Error = Failure("resource.unavailable");
            return response;
        }

        var input = new ParserInput(_resources.Input, (long)_frame.InputLength);
        var opened = await RunParserAsync(session, parserContext => parser.Open(input, request.Subimage, request.Mip, request.OutputFormat, parserContext), context.CancellationToken).ConfigureAwait(false);
        if (opened.Failure is not null)
        {
            parser.Dispose();
            response.Error = Failure(opened.Failure);
            return response;
        }

        var info = opened.Value!;
        if (!SandboxProfileCheck.IsValid(info) || info.Width > session.Limits.MaxWidth || info.Height > session.Limits.MaxHeight
            || (long)info.Channels.Count + info.Tags.Count + info.Warnings.Count > session.Limits.MaxItems)
        {
            parser.Dispose();
            response.Error = Failure("resource.parser_failed");
            return response;
        }

        lock (_gate)
        {
            session.Images[imageId] = new ImageState(parser, info, request.Subimage, request.Mip, request.OutputFormat);
        }

        response.Value = new ContentSandboxServiceOpenImageValue { ImageId = SandboxRecords.ToWireId(imageId) };
        return response;
    }

    /// <inheritdoc />
    public override Task<ContentSandboxServiceGetImageInfoResponse> GetImageInfo(ContentSandboxServiceGetImageInfoRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new ContentSandboxServiceGetImageInfoResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetLiveSession(request.SessionId, out var session) || !SandboxRecords.TryReadId(request.ImageId, out var imageId))
        {
            response.Error = Failure("validation.invalid_request");
            return Task.FromResult(response);
        }

        ImageState? image;
        lock (_gate)
        {
            _ = session.Images.TryGetValue(imageId, out image);
        }

        if (image is null)
        {
            response.Error = Failure("state.not_found");
            return Task.FromResult(response);
        }

        response.Value = new ContentSandboxServiceGetImageInfoValue { Info = image.Info.Clone() };
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task<ContentSandboxServiceReadImageTileResponse> ReadImageTile(ContentSandboxServiceReadImageTileRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new ContentSandboxServiceReadImageTileResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetLiveSession(request.SessionId, out var session)
            || !SandboxRecords.TryReadId(request.ImageId, out var imageId) || !SandboxProfileCheck.IsValid(request.Region))
        {
            response.Error = Failure("validation.invalid_request");
            return response;
        }

        ImageState? image;
        lock (_gate)
        {
            _ = session.Images.TryGetValue(imageId, out image);
        }

        if (image is null)
        {
            response.Error = Failure("state.not_found");
            return response;
        }

        var tile = await RenderTileAsync(
            session,
            request.Region,
            request.Grant,
            image.Format,
            image.Info.Width,
            image.Info.Height,
            (region, span, parserContext) => image.Parser.ReadTile(region, image.Format, span, parserContext),
            context.CancellationToken).ConfigureAwait(false);
        if (tile.Error is not null)
        {
            response.Error = tile.Error;
            return response;
        }

        response.Value = new ContentSandboxServiceReadImageTileValue { Buffer = tile.Descriptor };
        return response;
    }

    /// <inheritdoc />
    public override Task<ContentSandboxServiceCloseImageResponse> CloseImage(ContentSandboxServiceCloseImageRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new ContentSandboxServiceCloseImageResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetLiveSession(request.SessionId, out var session) || !SandboxRecords.TryReadId(request.ImageId, out var imageId))
        {
            response.Error = Failure("validation.invalid_request");
            return Task.FromResult(response);
        }

        ImageState? image;
        lock (_gate)
        {
            _ = session.Images.Remove(imageId, out image);
        }

        image?.Parser.Dispose();
        response.Value = new ContentSandboxServiceCloseImageValue { Receipt = ReceiptOf(request.Meta) };
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task<ContentSandboxServiceOpenPdfResponse> OpenPdf(ContentSandboxServiceOpenPdfRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new ContentSandboxServiceOpenPdfResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetLiveSession(request.SessionId, out var session) || !SandboxRecords.TryReadId(request.DocumentId, out var documentId))
        {
            response.Error = Failure("validation.invalid_request");
            return response;
        }

        PdfState? existing;
        lock (_gate)
        {
            _ = session.Documents.TryGetValue(documentId, out existing);
            if (existing is null && session.Documents.Count >= MaxOpenObjects)
            {
                response.Error = Failure("capacity.busy");
                return response;
            }
        }

        if (existing is not null)
        {
            response.Value = new ContentSandboxServiceOpenPdfValue { DocumentId = SandboxRecords.ToWireId(documentId), PageCount = existing.PageCount };
            return response;
        }

        var parser = _profile?.CreatePdfParser();
        if (parser is null)
        {
            response.Error = Failure("resource.unavailable");
            return response;
        }

        var input = new ParserInput(_resources.Input, (long)_frame.InputLength);
        var opened = await RunParserAsync(session, parserContext => parser.Open(input, parserContext), context.CancellationToken).ConfigureAwait(false);
        if (opened.Failure is not null)
        {
            parser.Dispose();
            response.Error = Failure(opened.Failure);
            return response;
        }

        if (opened.Value > session.Limits.MaxItems)
        {
            parser.Dispose();
            response.Error = Failure("resource.parser_failed");
            return response;
        }

        lock (_gate)
        {
            session.Documents[documentId] = new PdfState(parser, opened.Value);
        }

        response.Value = new ContentSandboxServiceOpenPdfValue { DocumentId = SandboxRecords.ToWireId(documentId), PageCount = opened.Value };
        return response;
    }

    /// <inheritdoc />
    public override async Task<ContentSandboxServiceGetPdfPageResponse> GetPdfPage(ContentSandboxServiceGetPdfPageRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new ContentSandboxServiceGetPdfPageResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetLiveSession(request.SessionId, out var session) || !SandboxRecords.TryReadId(request.DocumentId, out var documentId))
        {
            response.Error = Failure("validation.invalid_request");
            return response;
        }

        PdfState? document;
        lock (_gate)
        {
            _ = session.Documents.TryGetValue(documentId, out document);
        }

        if (document is null || request.PageIndex >= document.PageCount)
        {
            response.Error = Failure("state.not_found");
            return response;
        }

        var result = await RunParserAsync(session, parserContext => document.Parser.GetPage(request.PageIndex, parserContext), context.CancellationToken).ConfigureAwait(false);
        if (result.Failure is not null)
        {
            response.Error = Failure(result.Failure);
            return response;
        }

        var page = result.Value!;
        if (!SandboxProfileCheck.IsValid(page) || page.PageIndex != request.PageIndex)
        {
            response.Error = Failure("resource.parser_failed");
            return response;
        }

        lock (_gate)
        {
            document.Pages[request.PageIndex] = page.Clone();
        }

        response.Value = new ContentSandboxServiceGetPdfPageValue { Page = page };
        return response;
    }

    /// <inheritdoc />
    public override async Task<ContentSandboxServiceExtractPdfTextResponse> ExtractPdfText(ContentSandboxServiceExtractPdfTextRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new ContentSandboxServiceExtractPdfTextResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetLiveSession(request.SessionId, out var session) || !SandboxRecords.TryReadId(request.DocumentId, out var documentId))
        {
            response.Error = Failure("validation.invalid_request");
            return response;
        }

        PdfState? document;
        lock (_gate)
        {
            _ = session.Documents.TryGetValue(documentId, out document);
        }

        if (document is null || request.PageIndex >= document.PageCount)
        {
            response.Error = Failure("state.not_found");
            return response;
        }

        PdfPageText? pageText;
        lock (_gate)
        {
            _ = document.Texts.TryGetValue(request.PageIndex, out pageText);
        }

        if (pageText is null)
        {
            var result = await RunParserAsync(session, parserContext => document.Parser.GetPageText(request.PageIndex, parserContext), context.CancellationToken).ConfigureAwait(false);
            if (result.Failure is not null)
            {
                response.Error = Failure(result.Failure);
                return response;
            }

            pageText = result.Value!;
            if (pageText.Text.Length > 16 * 1024 * 1024 || pageText.Boxes.Any(box => !IsFinite(box)))
            {
                response.Error = Failure("resource.parser_failed");
                return response;
            }

            lock (_gate)
            {
                document.Texts[request.PageIndex] = pageText;
            }
        }

        HashSet<uint> allowed;
        lock (_gate)
        {
            if (!document.Starts.TryGetValue(request.PageIndex, out allowed!))
            {
                allowed = [0];
                document.Starts[request.PageIndex] = allowed;
            }
        }

        bool permitted;
        lock (_gate)
        {
            permitted = allowed.Contains(request.Start);
        }

        if (!permitted)
        {
            response.Error = Failure("validation.invalid_offset");
            return response;
        }

        var chunk = PdfTextPager.Cut(request.PageIndex, request.Start, pageText, session.Limits.MaxItems, MaxPdfTextBytes);
        if (chunk is null)
        {
            response.Error = Failure("resource.parser_failed");
            return response;
        }

        response.Value = new ContentSandboxServiceExtractPdfTextValue { Text = chunk };
        if (!SandboxProfileCheck.IsValid(response))
        {
            response.Value = null;
            response.Error = Failure("resource.parser_failed");
            return response;
        }

        if (chunk.HasNext)
        {
            lock (_gate)
            {
                _ = allowed.Add(chunk.Next);
            }
        }

        return response;
    }

    /// <inheritdoc />
    public override async Task<ContentSandboxServiceRenderPdfTileResponse> RenderPdfTile(ContentSandboxServiceRenderPdfTileRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var response = new ContentSandboxServiceRenderPdfTileResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetLiveSession(request.SessionId, out var session) || !SandboxRecords.TryReadId(request.DocumentId, out var documentId)
            || !SandboxProfileCheck.IsValid(request.Page) || !SandboxProfileCheck.IsValid(request.Region)
            || request.FullWidth == 0 || request.FullHeight == 0)
        {
            response.Error = Failure("validation.invalid_request");
            return response;
        }

        PdfState? document;
        SandboxPdfPage? known = null;
        lock (_gate)
        {
            _ = session.Documents.TryGetValue(documentId, out document);
            _ = document?.Pages.TryGetValue(request.Page.PageIndex, out known);
        }

        // The page geometry must be the one GetPdfPage returned; scaling is never inferred from untrusted fields.
        if (document is null || known is null || !known.Equals(request.Page))
        {
            response.Error = Failure(document is null ? "state.not_found" : "validation.invalid_request");
            return response;
        }

        var tile = await RenderTileAsync(
            session,
            request.Region,
            request.Grant,
            1,
            request.FullWidth,
            request.FullHeight,
            (region, span, parserContext) => document.Parser.RenderTile(request.Page, region, request.FullWidth, request.FullHeight, span, parserContext),
            context.CancellationToken).ConfigureAwait(false);
        if (tile.Error is not null)
        {
            response.Error = tile.Error;
            return response;
        }

        response.Value = new ContentSandboxServiceRenderPdfTileValue { Buffer = tile.Descriptor };
        return response;
    }

    /// <inheritdoc />
    public override Task<ContentSandboxServiceClosePdfResponse> ClosePdf(ContentSandboxServiceClosePdfRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new ContentSandboxServiceClosePdfResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetLiveSession(request.SessionId, out var session) || !SandboxRecords.TryReadId(request.DocumentId, out var documentId))
        {
            response.Error = Failure("validation.invalid_request");
            return Task.FromResult(response);
        }

        PdfState? document;
        lock (_gate)
        {
            _ = session.Documents.Remove(documentId, out document);
        }

        document?.Parser.Dispose();
        response.Value = new ContentSandboxServiceClosePdfValue { Receipt = ReceiptOf(request.Meta) };
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public override async Task<ContentSandboxServiceCancelSessionResponse> CancelSession(ContentSandboxServiceCancelSessionRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new ContentSandboxServiceCancelSessionResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetSession(request.SessionId, out var session))
        {
            response.Error = Failure("validation.invalid_request");
            return response;
        }

        // Withdraw every slot, signal every parser through its token and stop honouring new work. The process stays up until the parent
        // closes the session or terminates it after the five second grace.
        session.Broker?.Cancel();
        await session.Cancelled.CancelAsync().ConfigureAwait(false);
        response.Value = new ContentSandboxServiceCancelSessionValue { Receipt = ReceiptOf(request.Meta) };
        return response;
    }

    /// <inheritdoc />
    public override Task<ContentSandboxServiceCloseSessionResponse> CloseSession(ContentSandboxServiceCloseSessionRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = new ContentSandboxServiceCloseSessionResponse { Meta = MetaOf(request.Meta) };
        if (!Shape.IsValid(request) || !TryGetSession(request.SessionId, out var session))
        {
            response.Error = Failure("validation.invalid_request");
            return Task.FromResult(response);
        }

        CloseSessionState(session);
        response.Value = new ContentSandboxServiceCloseSessionValue { Receipt = ReceiptOf(request.Meta) };
        _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            _requestExit(ContentSandboxContract.ExitClean);
        });
        return Task.FromResult(response);
    }

    /// <summary>Ends the session and releases every parser. Idempotent.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        SessionState? session;
        lock (_gate)
        {
            session = _session;
        }

        if (session is not null)
        {
            CloseSessionState(session);
        }
    }

    private static string Reason(LocalRpcBrokerRefusal refusal) => refusal switch
    {
        LocalRpcBrokerRefusal.StaleSequence or LocalRpcBrokerRefusal.WrongSession => "state.stale_fence",
        LocalRpcBrokerRefusal.CapacityExceeded or LocalRpcBrokerRefusal.UnknownSlot or LocalRpcBrokerRefusal.RangeInvalid
            or LocalRpcBrokerRefusal.GeometryInvalid => "validation.invalid_request",
        LocalRpcBrokerRefusal.DigestMismatch => "resource.integrity_failed",
        LocalRpcBrokerRefusal.Cancelled or LocalRpcBrokerRefusal.Closed => "state.gone",
        _ => "state.invalid_transition",
    };

    private static ArcError Failure(string code) => TypedFailure.Create(code).ToWire();

    private static ResponseMeta MetaOf(RequestMeta? request) => new() { CorrelationId = request?.CorrelationId?.Clone() };

    private static Receipt ReceiptOf(RequestMeta? request) => new()
    {
        CommandId = request?.CommandId?.Clone(),
        Effect = EffectCertainty.Happened,
    };

    private long Ticks(TimeSpan span) => (long)(span.TotalSeconds * _clock.TimestampFrequency);

    private static bool IsFinite(SandboxTextBox box) =>
        double.IsFinite(box.X) && double.IsFinite(box.Y) && double.IsFinite(box.Width) && double.IsFinite(box.Height);

    private bool TryGetSession(Id? wire, [NotNullWhen(true)] out SessionState? session)
    {
        session = null;
        lock (_gate)
        {
            if (_session is { Broker: not null } current && SandboxRecords.TryReadId(wire, out var id) && id == current.SessionId)
            {
                session = current;
                return true;
            }
        }

        return false;
    }

    private bool TryGetLiveSession(Id? wire, [NotNullWhen(true)] out SessionState? session)
    {
        if (!TryGetSession(wire, out session))
        {
            return false;
        }

        lock (_gate)
        {
            if (session.Closed || session.Cancelled.IsCancellationRequested || session.LeaseEnds <= _clock.GetTimestamp())
            {
                session = null;
                return false;
            }
        }

        return true;
    }

    private void Release()
    {
        lock (_gate)
        {
            _session = null;
        }
    }

    private void CloseSessionState(SessionState session)
    {
        List<IDisposable> parsers = [];
        lock (_gate)
        {
            if (session.Closed)
            {
                return;
            }

            session.Closed = true;
            parsers.AddRange(session.Images.Values.Select(image => image.Parser));
            parsers.AddRange(session.Documents.Values.Select(document => document.Parser));
            session.Images.Clear();
            session.Documents.Clear();
        }

        session.Cancelled.Cancel();
        foreach (var parser in parsers)
        {
            parser.Dispose();
        }

        session.Broker?.Dispose();
    }

    /// <summary>
    /// Runs one parser call off the service thread under the launch deadline and the session cancellation. A parser that does not return in
    /// time cannot be preempted: the call fails, the parser lock is never released and the helper asks to exit.
    /// </summary>
    private async Task<ParserOutcome<T>> RunParserAsync<T>(SessionState session, Func<ParserContext, T> work, CancellationToken call)
    {
        var deadline = TimeSpan.FromMilliseconds(session.Limits.TimeoutMs);
        try
        {
            await session.ParserGate.WaitAsync(deadline, call).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is TimeoutException or OperationCanceledException)
        {
            return new ParserOutcome<T>(default, "capacity.busy");
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(session.Cancelled.Token, call);
        var context = new ParserContext(session.Limits, linked.Token);
        var task = Task.Factory.StartNew(() => work(context), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        try
        {
            var value = await task.WaitAsync(deadline, CancellationToken.None).ConfigureAwait(false);
            _ = session.ParserGate.Release();
            return new ParserOutcome<T>(value, null);
        }
        catch (TimeoutException)
        {
            // The parser ignored its token and its deadline: it holds its thread and the lock for good, and the process leaves.
            await linked.CancelAsync().ConfigureAwait(false);
            _requestExit(ContentSandboxContract.ExitParserHung);
            return new ParserOutcome<T>(default, "resource.parser_failed");
        }
        catch (Exception exception) when (exception is ContentParserException or OperationCanceledException or InvalidOperationException
            or ArgumentException or FormatException or IOException or OverflowException or InvalidDataException)
        {
            _ = session.ParserGate.Release();
            return new ParserOutcome<T>(default, "resource.parser_failed");
        }
    }

    /// <summary>
    /// The shared tile path: check the grant against what the parent granted, let the parser fill only that grant, seal exactly the bytes
    /// written, and return the descriptor only if it passes the same checks the parent will apply.
    /// </summary>
    private async Task<TileOutcome> RenderTileAsync(
        SessionState session,
        SandboxRegion region,
        SandboxSlotGrant? wireGrant,
        uint format,
        uint fullWidth,
        uint fullHeight,
        TileWork work,
        CancellationToken call)
    {
        if (!SandboxRecords.TryReadGrant(wireGrant, out var grant))
        {
            return TileOutcome.Fail(Failure("validation.invalid_request"));
        }

        LocalRpcSlotGrant? accepted;
        lock (_gate)
        {
            accepted = session.Grants.TryGetValue(grant.SlotId, out var held) ? held : null;
        }

        var pixelBytes = format == 1 ? 4UL : 16UL;
        var rowBytes = (ulong)region.Width * pixelBytes;
        if (accepted is null || accepted != grant || region.RowStride < rowBytes || region.Width > 2048 || region.Height > 2048
            || (ulong)region.X + region.Width > fullWidth || (ulong)region.Y + region.Height > fullHeight
            || region.Height * region.RowStride > grant.Capacity || fullWidth > session.Limits.MaxWidth || fullHeight > session.Limits.MaxHeight)
        {
            return TileOutcome.Fail(Failure("validation.invalid_request"));
        }

        var slot = _resources.Slots[(int)grant.SlotId];
        var capacity = checked((int)grant.Capacity);
        var required = ((region.Height - 1UL) * region.RowStride) + rowBytes;
        var written = await RunParserAsync(
            session,
            parserContext => work(region, slot.GetSpan(0, capacity), parserContext),
            call).ConfigureAwait(false);
        if (written.Failure is not null)
        {
            return TileOutcome.Fail(Failure(written.Failure));
        }

        if (written.Value < 0 || (ulong)written.Value < required || (ulong)written.Value > grant.Capacity)
        {
            return TileOutcome.Fail(Failure("resource.parser_failed"));
        }

        var sealed1 = session.Broker!.Seal(grant.SlotId, grant.Sequence, 0, slot.GetSpan(0, written.Value), region.RowStride);
        if (!sealed1.IsSuccess || sealed1.Value is null)
        {
            return TileOutcome.Fail(Failure(Reason(sealed1.Refusal)));
        }

        var descriptor = SandboxRecords.ToWire(sealed1.Value, new TileGeometry(format, fullWidth, fullHeight, region.X, region.Y, region.Width, region.Height));
        if (!SandboxProfileCheck.IsValid(descriptor, wireGrant!, region))
        {
            return TileOutcome.Fail(Failure("resource.parser_failed"));
        }

        return new TileOutcome(descriptor, null);
    }

    private delegate int TileWork(SandboxRegion region, Span<byte> destination, ParserContext context);

    private readonly record struct ParserOutcome<T>(T? Value, string? Failure);

    private sealed record TileOutcome(SandboxBufferDescriptor? Descriptor, ArcError? Error)
    {
        internal static TileOutcome Fail(ArcError error) => new(null, error);
    }

    private sealed class ImageState(IImageParser parser, SandboxImageInfo info, uint subimage, uint mip, uint format)
    {
        internal IImageParser Parser { get; } = parser;

        internal SandboxImageInfo Info { get; } = info;

        internal uint Format { get; } = format;

        internal uint Subimage { get; } = subimage;

        internal uint Mip { get; } = mip;

        internal bool Matches(uint otherSubimage, uint otherMip, uint otherFormat) =>
            Subimage == otherSubimage && Mip == otherMip && Format == otherFormat;
    }

    private sealed class PdfState(IPdfParser parser, uint pageCount)
    {
        internal IPdfParser Parser { get; } = parser;

        internal uint PageCount { get; } = pageCount;

        internal Dictionary<uint, SandboxPdfPage> Pages { get; } = [];

        internal Dictionary<uint, PdfPageText> Texts { get; } = [];

        internal Dictionary<uint, HashSet<uint>> Starts { get; } = [];
    }

    private sealed class SessionState
    {
        internal Guid SessionId { get; init; }

        internal LocalRpcBrokerChild? Broker { get; init; }

        internal ContentSandboxLimits Limits { get; init; } = new();

        internal long LeaseEnds { get; set; }

        internal bool Closed { get; set; }

        internal CancellationTokenSource Cancelled { get; } = new();

        internal SemaphoreSlim ParserGate { get; } = new(1, 1);

        internal Dictionary<uint, LocalRpcSlotGrant> Grants { get; } = [];

        internal Dictionary<Guid, ImageState> Images { get; } = [];

        internal Dictionary<Guid, PdfState> Documents { get; } = [];

        internal Dictionary<string, DateTimeOffset> Renewals { get; } = [];

        internal Queue<string> RenewalOrder { get; } = new();
    }
}
