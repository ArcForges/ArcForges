// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Globalization;
using Grpc.AspNetCore.Server;
using Grpc.Core;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http;

namespace ArcForges.LocalRpc;

/// <summary>
/// What the registration gate hands the owner's generated LocalBootstrap service implementation for one bootstrap call. It is created
/// only by the gate, for a call that reached the service through it, and it carries the connection the call arrived on, so the owner can
/// neither name another connection nor skip the gate. The owner maps the generated messages onto these three steps and answers any
/// refusal with one status (UNAUTHENTICATED) and no explanation.
/// </summary>
public sealed class LocalRpcBootstrapCall
{
    private readonly LocalRpcRegistration _registration;
    private readonly string _connectionId;
    private readonly CancellationToken _connectionClosed;
    private readonly bool _credentialsVerified;

    internal LocalRpcBootstrapCall(LocalRpcRegistration registration, string connectionId, bool credentialsVerified, CancellationToken connectionClosed)
    {
        _registration = registration;
        _connectionId = connectionId;
        _connectionClosed = connectionClosed;
        _credentialsVerified = credentialsVerified;
    }

    /// <summary>The registration this call belongs to.</summary>
    public LocalRpcRegistration Registration => _registration;

    /// <summary>
    /// Challenge: the child names its instance id, sends 32 random bytes and states the child kind, build and protocol it claims. The
    /// parent answers with a challenge of at most five seconds, its own 32 random bytes and its instance id.
    /// </summary>
    public LocalRpcRegistrationRefusal TryChallenge(
        Guid callerInstanceId,
        ReadOnlySpan<byte> clientChallenge,
        LocalRpcLaunchIdentity claimed,
        out LocalRpcBootstrapChallenge? challenge) =>
        _registration.TryChallenge(_connectionId, callerInstanceId, clientChallenge, claimed, out challenge);

    /// <summary>Confirm: the child proves possession of the launch secret over the transcript. See <see cref="LocalRpcRegistration"/>.</summary>
    public LocalRpcRegistrationRefusal TryConfirm(Guid challengeId, ReadOnlySpan<byte> proof, out LocalRpcRegistrationGrant? grant) =>
        _registration.TryConfirm(_connectionId, challengeId, proof, _connectionClosed, out grant);

    /// <summary>Renew: extends the lease to 30 seconds from now. Only a call that carried verified credentials may renew.</summary>
    public LocalRpcRegistrationRefusal TryRenew(ReadOnlySpan<byte> commandId, out DateTimeOffset expiresAtUtc)
    {
        expiresAtUtc = default;
        return _credentialsVerified
            ? _registration.TryRenew(_connectionId, commandId, out expiresAtUtc)
            : LocalRpcRegistrationRefusal.NotRegistered;
    }
}

/// <summary>Reaches the bootstrap call the registration gate attached to a gRPC call.</summary>
public static class LocalRpcServerCallContextExtensions
{
    /// <summary>
    /// The bootstrap call of the gate that admitted this call, or null when no registration gate served it (a server without
    /// <see cref="LocalRpcServerBuilder.RequireRegistration"/>): a service must answer such a call with a refusal.
    /// </summary>
    public static LocalRpcBootstrapCall? GetBootstrapCall(this ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.GetHttpContext().Items.TryGetValue(LocalRpcRegistrationGate.CallKey, out var call) ? call as LocalRpcBootstrapCall : null;
    }
}

/// <summary>
/// The call gate of a server that serves a registration. Before routing, so before any handler, queue or unknown-service answer,
/// every call except the two bootstrap steps of an unregistered child must present valid credentials; one answer (UNAUTHENTICATED,
/// no explanation) covers every refusal so the gate is no oracle.
/// </summary>
internal static class LocalRpcRegistrationGate
{
    internal const string PeerHeader = "x-af-peer-bin";
    internal const string InstanceHeader = "x-af-instance-bin";
    internal const string ContractSetHeader = "x-af-contract-set";

    internal static readonly object CallKey = new();

    internal static Func<HttpContext, RequestDelegate, Task> Create(LocalRpcRegistration registration) =>
        (context, next) => InvokeAsync(registration, context, next);

    private static Task InvokeAsync(LocalRpcRegistration registration, HttpContext context, RequestDelegate next)
    {
        var path = context.Request.Path.Value ?? string.Empty;
        var connectionId = context.Connection.Id;
        var closed = context.Features.Get<IConnectionLifetimeFeature>()?.ConnectionClosed ?? CancellationToken.None;
        if (string.Equals(path, LocalRpcRegistration.ChallengePath, StringComparison.Ordinal)
            || string.Equals(path, LocalRpcRegistration.ConfirmPath, StringComparison.Ordinal))
        {
            // The two steps of an unregistered child: served only while the registration awaits its bootstrap.
            if (!registration.AdmitsBootstrapCalls)
            {
                return Refuse(context);
            }

            context.Items[CallKey] = new LocalRpcBootstrapCall(registration, connectionId, credentialsVerified: false, closed);
            return next(context);
        }

        Span<byte> nonce = stackalloc byte[LocalRpcRegistration.NonceLength];
        Span<byte> contractSet = stackalloc byte[LocalRpcLaunchIdentity.DigestLength];
        if (!TryReadCredentials(context.Request.Headers, nonce, out var instance, contractSet)
            || registration.Authorize(connectionId, nonce, instance, contractSet) != LocalRpcRegistrationRefusal.None)
        {
            return Refuse(context);
        }

        context.Items[CallKey] = new LocalRpcBootstrapCall(registration, connectionId, credentialsVerified: true, closed);
        return next(context);
    }

    /// <summary>Reads the three credential headers; any missing, repeated, malformed or mis-sized one fails.</summary>
    internal static bool TryReadCredentials(IHeaderDictionary headers, Span<byte> nonce, out Guid instance, Span<byte> contractSet)
    {
        instance = Guid.Empty;
        Span<byte> instanceBytes = stackalloc byte[16];
        if (!TryDecodeBinary(headers[PeerHeader], nonce) || !TryDecodeBinary(headers[InstanceHeader], instanceBytes))
        {
            return false;
        }

        var contract = headers[ContractSetHeader];
        if (contract.Count != 1 || contract[0] is not { Length: LocalRpcLaunchIdentity.DigestLength * 2 } hex || !TryDecodeHex(hex, contractSet))
        {
            return false;
        }

        instance = new Guid(instanceBytes, bigEndian: true);
        return true;
    }

    /// <summary>
    /// Decodes a gRPC binary header (base64, padding optional) into exactly <paramref name="destination"/>'s length. Anything else
    /// (no value, several values, another length, bad characters) fails; the input is bounded before any decoding.
    /// </summary>
    internal static bool TryDecodeBinary(Microsoft.Extensions.Primitives.StringValues values, Span<byte> destination)
    {
        if (values.Count != 1 || values[0] is not { } text)
        {
            return false;
        }

        var maximum = ((destination.Length + 2) / 3 * 4) + 4;
        if (text.Length > maximum || text.Length == 0)
        {
            return false;
        }

        Span<char> padded = stackalloc char[maximum];
        text.AsSpan().CopyTo(padded);
        var length = text.Length;
        while (length % 4 != 0)
        {
            padded[length++] = '=';
        }

        Span<byte> decoded = stackalloc byte[maximum];
        return Convert.TryFromBase64Chars(padded[..length], decoded, out var written)
            && written == destination.Length
            && Copy(decoded[..written], destination);
    }

    /// <summary>Decodes exactly <c>2 * destination.Length</c> hexadecimal digits, upper or lower case.</summary>
    internal static bool TryDecodeHex(string hex, Span<byte> destination)
    {
        if (hex.Length != destination.Length * 2)
        {
            return false;
        }

        for (var index = 0; index < destination.Length; index++)
        {
            var high = Digit(hex[2 * index]);
            var low = Digit(hex[(2 * index) + 1]);
            if (high < 0 || low < 0)
            {
                return false;
            }

            destination[index] = (byte)((high << 4) | low);
        }

        return true;
    }

    private static int Digit(char value) => value switch
    {
        >= '0' and <= '9' => value - '0',
        >= 'a' and <= 'f' => value - 'a' + 10,
        >= 'A' and <= 'F' => value - 'A' + 10,
        _ => -1,
    };

    private static bool Copy(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        source.CopyTo(destination);
        return true;
    }

    /// <summary>A trailers-only UNAUTHENTICATED answer that names nothing about the cause.</summary>
    private static Task Refuse(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/grpc";
        context.Response.Headers["grpc-status"] = ((int)StatusCode.Unauthenticated).ToString(CultureInfo.InvariantCulture);
        context.Response.Headers["grpc-message"] = "Registration is required.";
        return Task.CompletedTask;
    }
}
