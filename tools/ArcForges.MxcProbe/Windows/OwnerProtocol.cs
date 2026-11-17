// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace ArcForges.MxcProbe;

// Private, short-lived experiment configuration. Never include this object in
// an evidence report: the two capabilities deliberately have different roles.
internal sealed record ProbeOwnerConfig(string RunId, string OwnerEpoch, long Generation,
    string SnapshotDigest, string PipeName, string ControllerKey, string ObserverKey,
    ConPtyLaunchOptions Launch, string? PauseAtPhase = null)
{
    public override string ToString() => "ProbeOwnerConfig (private capabilities omitted)";
}

internal sealed record ProbeOwnerHello(string RunId, string OwnerEpoch, long Generation,
    string SnapshotDigest, bool Observer);
internal sealed record ProbeOwnerChallenge(string Nonce, string Proof);
internal sealed record ProbeOwnerProof(string Proof);

internal sealed record ProbeOwnerRequest
{
    public required string Operation { get; init; }
    public long Generation { get; init; }
    public string? LeaseId { get; init; }
    public long Sequence { get; init; }
    public byte[]? Input { get; init; }
    public int Columns { get; init; }
    public int Rows { get; init; }
    public long Cursor { get; init; }
    public int MaxBytes { get; init; } = 32_768;
    public ConPtyLimits? Limits { get; init; }
    public override string ToString() => "ProbeOwnerRequest (terminal control omitted)";
}

internal sealed record ProbeOwnerResponse
{
    public bool Ok { get; init; }
    public string? Error { get; init; }
    public string Effect { get; init; } = "NONE";
    public required long Generation { get; init; }
    public required string State { get; init; }
    public bool CleanupConfirmed { get; init; }
    public bool DataDeletionAllowed { get; init; }
    public string? LeaseId { get; init; }
    public DateTimeOffset? LeaseExpiresUtc { get; init; }
    public ConPtyReplay? Replay { get; init; }
    public ConPtyJobObservation? Job { get; init; }
    public int OwnerPid { get; init; }
    public DateTimeOffset OwnerCreatedUtc { get; init; }
    public uint? ExecutorPid { get; init; }
    public DateTimeOffset? ExecutorCreatedUtc { get; init; }
    public uint? RawExitCode { get; init; }
    public string ExitSource { get; init; } = "unknown";
    public override string ToString() => "ProbeOwnerResponse (terminal capability omitted)";
}

// Only a bounded binary frame is used; terminal bytes never become log text.
// The server proves possession first, so an unrelated same-user pipe cannot
// obtain either capability from a reconnecting client.
internal static class OwnerProtocol
{
    internal const int MaxFrameBytes = 98_304;

    public static async Task<ProbeOwnerResponse> SendAsync(ProbeOwnerConfig config, ProbeOwnerRequest request,
        bool observer = false, CancellationToken cancellationToken = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        await using var pipe = new NamedPipeClientStream(".", config.PipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, TokenImpersonationLevel.Anonymous);
        await pipe.ConnectAsync(deadline.Token).ConfigureAwait(false);
        var hello = new ProbeOwnerHello(config.RunId, config.OwnerEpoch, request.Generation, config.SnapshotDigest, observer);
        await WriteAsync(pipe, hello, OwnerJson.Default.ProbeOwnerHello, deadline.Token).ConfigureAwait(false);
        var challenge = await ReadAsync(pipe, OwnerJson.Default.ProbeOwnerChallenge, deadline.Token).ConfigureAwait(false);
        var key = Convert.FromBase64String(observer ? config.ObserverKey : config.ControllerKey);
        try
        {
            if (key.Length != 32 || !Verify(key, hello, challenge.Nonce, "server", challenge.Proof))
                throw new UnauthorizedAccessException("Owner authentication failed.");
            await WriteAsync(pipe, new ProbeOwnerProof(Mac(key, hello, challenge.Nonce, "client")),
                OwnerJson.Default.ProbeOwnerProof, deadline.Token).ConfigureAwait(false);
            await WriteAsync(pipe, request, OwnerJson.Default.ProbeOwnerRequest, deadline.Token).ConfigureAwait(false);
            return await ReadAsync(pipe, OwnerJson.Default.ProbeOwnerResponse, deadline.Token).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    internal static string Mac(byte[] key, ProbeOwnerHello hello, string nonce, string side)
    {
        // All identity fields are validated before they enter this transcript.
        var transcript = string.Join('\n', "afv2-mxc-owner-v1", side, hello.RunId, hello.OwnerEpoch,
            hello.Generation.ToString(System.Globalization.CultureInfo.InvariantCulture), hello.SnapshotDigest,
            hello.Observer ? "observer" : "controller", nonce);
        return Convert.ToBase64String(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(transcript)));
    }

    internal static bool Verify(byte[] key, ProbeOwnerHello hello, string nonce, string side, string proof)
    {
        Span<byte> provided = stackalloc byte[32];
        if (nonce.Length != 44 || !Convert.TryFromBase64String(proof, provided, out var count) || count != 32) return false;
        return CryptographicOperations.FixedTimeEquals(provided, Convert.FromBase64String(Mac(key, hello, nonce, side)));
    }

    internal static async Task WriteAsync<T>(Stream stream, T value, JsonTypeInfo<T> type, CancellationToken cancellationToken)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, type);
        if (bytes.Length is < 1 or > MaxFrameBytes) throw new InvalidDataException("Owner frame is too large.");
        var length = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(length, bytes.Length);
        await stream.WriteAsync(length, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<T> ReadAsync<T>(Stream stream, JsonTypeInfo<T> type, CancellationToken cancellationToken)
    {
        var length = new byte[4];
        await stream.ReadExactlyAsync(length, cancellationToken).ConfigureAwait(false);
        var count = BinaryPrimitives.ReadInt32LittleEndian(length);
        if (count is < 1 or > MaxFrameBytes) throw new InvalidDataException("Invalid owner frame length.");
        var bytes = new byte[count];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize(bytes, type) ?? throw new InvalidDataException("Empty owner frame.");
    }
}

[JsonSourceGenerationOptions(WriteIndented = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(ProbeOwnerConfig))]
[JsonSerializable(typeof(ProbeOwnerHello))]
[JsonSerializable(typeof(ProbeOwnerChallenge))]
[JsonSerializable(typeof(ProbeOwnerProof))]
[JsonSerializable(typeof(ProbeOwnerRequest))]
[JsonSerializable(typeof(ProbeOwnerResponse))]
[JsonSerializable(typeof(ProbeOwnerRecord))]
internal sealed partial class OwnerJson : JsonSerializerContext;
