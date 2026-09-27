// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Text.Json;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;

namespace ArcForges.Security;

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
        var buffer = new ArrayBufferWriter<byte>();
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

        if (buffer.WrittenCount > MaximumBytes)
        {
            throw new ArgumentException("Actor snapshot exceeds the boundary limit.", nameof(chain));
        }

        return buffer.WrittenSpan.ToArray();
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
