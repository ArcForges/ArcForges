// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Text.Json;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;

namespace ArcForges.Security;

/// <summary>A growable JSON target that never retains more than its caller's byte budget.</summary>
internal sealed class CappedSnapshotBufferWriter(int maximumBytes, string message, string parameterName) : IBufferWriter<byte>
{
    private byte[] _buffer = new byte[Math.Min(maximumBytes, 256)];
    private int _written;
    private int _available;

    public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, _written);

    public void Advance(int count)
    {
        if (count < 0 || count > _available)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        _written += count;
        _available = 0;
    }

    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        EnsureCapacity(sizeHint);
        _available = _buffer.Length - _written;
        return _buffer.AsMemory(_written, _available);
    }

    public Span<byte> GetSpan(int sizeHint = 0)
    {
        EnsureCapacity(sizeHint);
        _available = _buffer.Length - _written;
        return _buffer.AsSpan(_written, _available);
    }

    public byte[] ToArray() => WrittenSpan.ToArray();

    private void EnsureCapacity(int sizeHint)
    {
        if (sizeHint < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(sizeHint));
        }

        var required = (long)_written + Math.Max(sizeHint, 1);
        if (required > maximumBytes)
        {
            throw new ArgumentException(message, parameterName);
        }

        if (required > _buffer.Length)
        {
            var newCapacity = (int)Math.Min(maximumBytes, Math.Max(required, (long)_buffer.Length * 2));
            Array.Resize(ref _buffer, newCapacity);
        }
    }
}

/// <summary>
/// Internal boundary evidence, not a public Contracts wire schema or credential. A receiving
/// authenticated transport must bind this evidence to its caller and expected owner before use.
/// No integrity, freshness, replay protection, or authentication is inferred from decoding.
/// </summary>
public sealed class UntrustedActorChainEvidence
{
    internal UntrustedActorChainEvidence(ActorChain chain) => Chain = chain;
    public ActorChain Chain { get; }
}

/// <summary>Bounded, lossless offline queue/process-boundary snapshot of complete provenance.</summary>
public static class ActorChainSnapshot
{
    public const int MaximumBytes = 65536;

    public static byte[] Encode(ActorChain chain)
    {
        ArgumentNullException.ThrowIfNull(chain);
        var buffer = new CappedSnapshotBufferWriter(MaximumBytes, "Actor snapshot exceeds the boundary limit.", nameof(chain));
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("version", 1);
            writer.WriteString("realm", chain.Owner.Realm.Value);
            writer.WriteString("owner", chain.Owner.Id.Value);
            writer.WriteNumber("humanKind", (int)chain.Owner.Kind);
            writer.WriteString("device", chain.Device.Value);
            writer.WriteString("installation", chain.Installation.Value);
            writer.WriteString("session", chain.Session.Value);
            writer.WriteString("callerInstance", chain.CallerInstance.Value);
            writer.WriteNumber("actorCount", chain.Actors.Count);
            writer.WriteStartArray("actors");
            foreach (var actor in chain.Actors)
            {
                writer.WriteStartObject();
                writer.WriteNumber("kind", (int)actor.Kind);
                writer.WriteString("actor", actor.ActorId);
                writer.WriteString("executor", actor.Executor.Value);
                writer.WriteString("software", actor.SoftwareIdentity);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    public static UntrustedActorChainEvidence Decode(ReadOnlySpan<byte> snapshot)
    {
        if (snapshot.Length is 0 or > MaximumBytes)
        {
            throw new ArgumentException("Actor snapshot size is invalid.", nameof(snapshot));
        }

        // Own the bytes: caller mutation must not change data while it is inspected.
        using var document = JsonDocument.Parse(snapshot.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        RequireFields(root, "version", "realm", "owner", "humanKind", "device", "installation", "session", "callerInstance", "actorCount", "actors");
        if (root.GetProperty("version").GetInt32() != 1)
        {
            throw new JsonException("Unsupported actor snapshot version.");
        }

        var items = root.GetProperty("actors");
        var count = root.GetProperty("actorCount").GetInt32();
        if (items.ValueKind != JsonValueKind.Array || count < 0 || count > ActorChain.MaximumDelegatedActors || items.GetArrayLength() != count)
        {
            throw new JsonException("Actor snapshot has an invalid or incomplete delegation sequence.");
        }

        var actors = new List<DelegatedActor>(count);
        foreach (var item in items.EnumerateArray())
        {
            RequireFields(item, "kind", "actor", "executor", "software");
            actors.Add(new DelegatedActor((ActorKind)item.GetProperty("kind").GetInt32(),
                item.GetProperty("actor").GetGuid(), new InstanceId(item.GetProperty("executor").GetGuid()),
                item.GetProperty("software").GetString() ?? throw new JsonException("Missing software identity.")));
        }

        return new UntrustedActorChainEvidence(new ActorChain(
            new HumanPrincipal(new RealmId(root.GetProperty("realm").GetGuid()), new UserId(root.GetProperty("owner").GetGuid()), (HumanIdentityKind)root.GetProperty("humanKind").GetInt32()),
            new DeviceId(root.GetProperty("device").GetGuid()),
            new InstallationId(root.GetProperty("installation").GetGuid()),
            new SessionId(root.GetProperty("session").GetGuid()),
            new InstanceId(root.GetProperty("callerInstance").GetGuid()), actors));
    }

    private static void RequireFields(JsonElement value, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("Actor snapshot object expected.");
        }

        var remaining = new HashSet<string>(names, StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!remaining.Remove(property.Name))
            {
                throw new JsonException("Unknown or duplicate actor snapshot field.");
            }
        }

        if (remaining.Count != 0)
        {
            throw new JsonException("Incomplete actor snapshot.");
        }
    }
}

/// <summary>Bounded serialization for marked instruction input; decoding never upgrades provenance.</summary>
public static class InstructionSnapshot
{
    public const int MaximumBytes = 1_048_576;

    public static byte[] Encode(InstructionInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var buffer = new CappedSnapshotBufferWriter(MaximumBytes, "Instruction snapshot exceeds the boundary limit.", nameof(input));
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("version", 1);
            writer.WriteNumber("origin", (int)input.Provenance.Origin);
            writer.WriteString("sourceReference", input.Provenance.SourceReference);
            writer.WriteString("content", input.Content);
            writer.WriteString("inputSha256", input.Provenance.InputSha256);
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    public static InstructionInput Decode(ReadOnlySpan<byte> snapshot)
    {
        if (snapshot.Length is 0 or > MaximumBytes)
        {
            throw new ArgumentException("Instruction snapshot size is invalid.", nameof(snapshot));
        }

        using var document = JsonDocument.Parse(snapshot.ToArray(), new JsonDocumentOptions { MaxDepth = 4 });
        var root = document.RootElement;
        RequireFields(root, "version", "origin", "sourceReference", "content", "inputSha256");
        if (!root.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.Number ||
            !version.TryGetInt32(out var versionNumber) || versionNumber != 1)
        {
            throw new JsonException("Unsupported instruction snapshot version.");
        }

        if (!root.TryGetProperty("origin", out var originValue) || originValue.ValueKind != JsonValueKind.Number ||
            !originValue.TryGetInt32(out var originNumber) || !Enum.IsDefined((InstructionOrigin)originNumber))
        {
            throw new JsonException("Instruction snapshot origin is invalid.");
        }

        var sourceReference = ReadString(root, "sourceReference");
        var content = ReadString(root, "content");
        var inputSha256 = ReadString(root, "inputSha256");
        try
        {
            return InstructionInput.Restore((InstructionOrigin)originNumber, sourceReference, content, inputSha256);
        }
        catch (ArgumentException exception)
        {
            throw new JsonException("Instruction snapshot provenance is invalid.", exception);
        }
    }

    private static string ReadString(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String || property.GetString() is not { } result)
        {
            throw new JsonException($"Instruction snapshot field '{name}' is invalid.");
        }

        return result;
    }

    private static void RequireFields(JsonElement value, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("Instruction snapshot object expected.");
        }

        var remaining = new HashSet<string>(names, StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!remaining.Remove(property.Name))
            {
                throw new JsonException("Unknown or duplicate instruction snapshot field.");
            }
        }

        if (remaining.Count != 0)
        {
            throw new JsonException("Incomplete instruction snapshot.");
        }
    }
}
