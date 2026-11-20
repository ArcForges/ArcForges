// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.LocalRpc;
using Google.Protobuf;

namespace ArcForges.CommandLine;

// The relay carries only a detach request. The attachment still owns the only connection that may release the lease.
internal sealed class TerminalDetachRelay : IAsyncDisposable
{
    private const int IdBytes = 16;
    private const int RequestBytes = 4 + 2 * IdBytes;
    private const int ReplyHeaderBytes = RequestBytes + sizeof(int);
    private const int MaxErrorBytes = 16 * 1024;
    private const int ConnectTimeoutMilliseconds = 750;
    private static readonly TimeSpan s_frameTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan s_requestTimeout = TimeSpan.FromSeconds(15);
    private static readonly byte[] s_receipt = [1];

    private readonly NamedPipeServerStream _pipe;
    private readonly byte[] _request;
    private readonly CancellationTokenSource _stop;
    private int _replyStarted;

    private TerminalDetachRelay(NamedPipeServerStream pipe, byte[] request, CancellationToken cancellationToken)
    {
        _pipe = pipe;
        _request = request;
        _stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Received = ReceiveAsync(_stop.Token);
    }

    internal Task Received { get; }

    internal static Task<TerminalDetachRelay> OpenAsync(Id runId, Id leaseId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var request = CreateRequest(runId, leaseId);
        try
        {
            string address = PipeAddress(request, createDirectory: true);
            var pipe = OperatingSystem.IsWindows() ? CreateWindowsServer(address)
                : new NamedPipeServerStream(address, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance);
            return Task.FromResult(new TerminalDetachRelay(pipe, request, cancellationToken));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new V2CommandException(Unavailable("terminal_detach_endpoint_unavailable"), identity: null);
        }
    }

    internal async Task ReplyAsync(ArcError? error, CancellationToken cancellationToken)
    {
        if (!Received.IsCompletedSuccessfully || Interlocked.Exchange(ref _replyStarted, 1) != 0)
        {
            throw new InvalidOperationException("A terminal detach relay replies once to its validated request.");
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(s_frameTimeout);
        if (error?.CalculateSize() > MaxErrorBytes)
        {
            return;
        }

        var payload = error is null ? Array.Empty<byte>() : error.ToByteArray();
        var frame = new byte[ReplyHeaderBytes + payload.Length];
        _request.CopyTo(frame, 0);
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(RequestBytes, sizeof(int)), payload.Length);
        payload.CopyTo(frame, ReplyHeaderBytes);
        try
        {
            await _pipe.WriteAsync(frame, deadline.Token).ConfigureAwait(false);
            // Keep the Windows pipe open until the requester has read the whole response.
            var receipt = new byte[1];
            _ = await _pipe.ReadAsync(receipt, deadline.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or OperationCanceledException)
        {
            // The requester's loss cannot change the already observed terminal outcome.
        }
    }

    internal static async Task<int> RequestAsync(Cli cli, Id runId, Id leaseId, CancellationToken cancellationToken)
    {
        var request = CreateRequest(runId, leaseId);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(cli.Timeout ?? s_requestTimeout);
        bool sent = false;
        try
        {
            string address = PipeAddress(request, createDirectory: false);
            await using var pipe = OperatingSystem.IsWindows() ? CreateWindowsClient(address)
                : new NamedPipeClientStream(".", address, PipeDirection.InOut,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await pipe.ConnectAsync(ConnectTimeoutMilliseconds, deadline.Token).ConfigureAwait(false);
            if (OperatingSystem.IsWindows() && !NodeConnector.IsOwnedByCurrentUser(pipe, out _))
            {
                return V2Cli.Fail(cli, AccessDenied());
            }

            deadline.Token.ThrowIfCancellationRequested();
            sent = true;
            await pipe.WriteAsync(request, deadline.Token).ConfigureAwait(false);
            var header = new byte[ReplyHeaderBytes];
            await pipe.ReadExactlyAsync(header, deadline.Token).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(header.AsSpan(0, RequestBytes), request))
            {
                return V2Cli.Fail(cli, Unconfirmed());
            }

            var length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(RequestBytes, sizeof(int)));
            if (length is < 0 or > MaxErrorBytes)
            {
                return V2Cli.Fail(cli, Unconfirmed());
            }

            ArcError? error = null;
            if (length > 0)
            {
                var payload = new byte[length];
                await pipe.ReadExactlyAsync(payload, deadline.Token).ConfigureAwait(false);
                error = ArcError.Parser.ParseFrom(payload);
                if (error.Code.Length == 0)
                {
                    return V2Cli.Fail(cli, Unconfirmed());
                }
            }

            await AcknowledgeReplyAsync(pipe, deadline.Token).ConfigureAwait(false);
            return error is null
                ? V2Cli.Print(cli, new JsonObject { ["runId"] = IdText.Format(runId), ["detached"] = true })
                : V2Cli.Fail(cli, error);
        }
        catch (UnauthorizedAccessException) when (!sent)
        {
            return V2Cli.Fail(cli, AccessDenied());
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or OperationCanceledException or UnauthorizedAccessException)
        {
            return V2Cli.Fail(cli, sent ? Unconfirmed() : Unavailable("terminal_attachment_endpoint_absent"));
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        try
        {
            await Received.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
        }
        finally
        {
            _stop.Dispose();
            await _pipe.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task ReceiveAsync(CancellationToken cancellationToken)
    {
        var frame = new byte[RequestBytes];
        while (true)
        {
            try
            {
                await _pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(s_frameTimeout);
            bool valid = false;
            try
            {
                await _pipe.ReadExactlyAsync(frame, deadline.Token).ConfigureAwait(false);
                valid = CryptographicOperations.FixedTimeEquals(frame, _request)
                    && (!OperatingSystem.IsWindows() || IsWindowsPeerCurrentUser(_pipe));
                if (valid)
                {
                    return;
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or OperationCanceledException)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }
            finally
            {
                if (!valid)
                {
                    _pipe.Disconnect();
                }
            }
        }
    }

    private static async Task AcknowledgeReplyAsync(Stream stream, CancellationToken cancellationToken)
    {
        try
        {
            await stream.WriteAsync(s_receipt, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or OperationCanceledException)
        {
            // The result was already read and validated completely.
        }
    }

    private static byte[] CreateRequest(Id runId, Id leaseId)
    {
        if (runId.Value.Length != IdBytes || leaseId.Value.Length != IdBytes)
        {
            throw new UsageException("A terminal detach request requires exact Run and lease IDs.");
        }

        var request = new byte[RequestBytes];
        "AFD2"u8.CopyTo(request);
        runId.Value.Span.CopyTo(request.AsSpan(4, IdBytes));
        leaseId.Value.Span.CopyTo(request.AsSpan(4 + IdBytes, IdBytes));
        return request;
    }

    private static string PipeAddress(byte[] request, bool createDirectory)
    {
        string digest = Convert.ToHexStringLower(SHA256.HashData(request));
        if (OperatingSystem.IsWindows())
        {
            return "arcforges-detach-" + LocalRpcEndpoint.CurrentUserHash + "-" + digest;
        }

        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("Local terminal detach is supported on Windows and Linux.");
        }

        string directory = Path.Combine("/tmp", "afcli-" + LocalRpcEndpoint.CurrentUserHash[..16]);
        const UnixFileMode ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        if (createDirectory)
        {
            _ = Directory.CreateDirectory(directory, ownerOnly);
        }

        if (new DirectoryInfo(directory).LinkTarget is not null || (File.GetUnixFileMode(directory) & ~ownerOnly) != 0)
        {
            throw new UnauthorizedAccessException("The terminal relay directory is not private.");
        }

        return Path.Combine(directory, "d-" + digest);
    }

    [SupportedOSPlatform("windows")]
    private static NamedPipeServerStream CreateWindowsServer(string address)
    {
        using var current = WindowsIdentity.GetCurrent();
        var user = current.User ?? throw new UnauthorizedAccessException("The current token has no user SID.");
        var security = new PipeSecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize,
            AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(address, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, security);
    }

    [SupportedOSPlatform("windows")]
    private static NamedPipeClientStream CreateWindowsClient(string address) => new(".", address,
        PipeAccessRights.ReadWrite | PipeAccessRights.ReadPermissions | PipeAccessRights.Synchronize,
        PipeOptions.Asynchronous, TokenImpersonationLevel.Identification, HandleInheritability.None);

    [SupportedOSPlatform("windows")]
    private static bool IsWindowsPeerCurrentUser(NamedPipeServerStream pipe)
    {
        using var current = WindowsIdentity.GetCurrent();
        var user = current.User;
        bool matches = false;
        pipe.RunAsClient(() =>
        {
            using var peer = WindowsIdentity.GetCurrent(ifImpersonating: true);
            matches = NodeConnector.OwnerIsUser(peer?.User, user);
        });
        return matches;
    }

    private static ArcError Unavailable(string reason) =>
        V2Cli.Error(ErrorCategory.State, "terminal_unavailable", reason);

    private static ArcError AccessDenied() =>
        V2Cli.Error(ErrorCategory.Authorization, "permission_denied", "terminal_local_connection_required");

    private static ArcError Unconfirmed()
    {
        var error = V2Cli.Error(ErrorCategory.Execution, "terminal_ack_unavailable", "terminal_acknowledgment_unavailable");
        error.Effect = EffectCertainty.Unknown;
        return error;
    }
}
