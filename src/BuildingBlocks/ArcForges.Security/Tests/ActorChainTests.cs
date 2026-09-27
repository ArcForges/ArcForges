// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;
using Xunit;

namespace ArcForges.Security.Tests;

public sealed class ActorChainTests
{
    private static ActorChain Create(HumanIdentityKind human = HumanIdentityKind.CloudUser) => new(
        new HumanPrincipal(new RealmId(Guid.NewGuid()), new UserId(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff")), human),
        new DeviceId(Guid.NewGuid()), new InstallationId(Guid.NewGuid()),
        SessionId.New(), new InstanceId(Guid.NewGuid()),
        [Actor(ActorKind.Automation), Actor(ActorKind.Agent), Actor(ActorKind.Extension), Actor(ActorKind.InternalService)]);

    private static DelegatedActor Actor(ActorKind kind) => new(kind, Guid.NewGuid(), new InstanceId(Guid.NewGuid()), "owned.software/1");

    [Theory]
    [InlineData(HumanIdentityKind.CloudUser)]
    [InlineData(HumanIdentityKind.LocalHuman)]
    public void FullChainSurvivesLayerQueueAndOfflineProcessBoundary(HumanIdentityKind human)
    {
        var original = Create(human);
        var entry = new ActorOperation<string>(original, "request");
        var layer = entry.Forward(42);
        Assert.Same(original, layer.Actors);
        var queue = new Queue<byte[]>();
        queue.Enqueue(ActorChainSnapshot.Encode(layer.Actors));
        var transported = queue.Dequeue().ToArray();
        var evidence = ActorChainSnapshot.Decode(transported);
        Array.Fill(transported, (byte)0);
        var restored = evidence.Chain;
        Assert.Equal(original.Owner, restored.Owner);
        Assert.Equal(original.Device, restored.Device);
        Assert.Equal(original.Installation, restored.Installation);
        Assert.Equal(original.Session, restored.Session);
        Assert.Equal(original.CallerInstance, restored.CallerInstance);
        Assert.Equal(original.Actors, restored.Actors);
        Assert.Equal(ActorChainSnapshot.Encode(original), ActorChainSnapshot.Encode(restored));
        Assert.IsType<UntrustedActorChainEvidence>(evidence);
    }

    [Fact]
    public void OperationCannotBeConstructedWithoutCompleteProvenance()
    {
        Assert.Throws<ArgumentNullException>(() => new ActorOperation<string>(null!, "request"));
        var chain = Create();
        Assert.Throws<ArgumentNullException>(() => new ActorChain(null!, chain.Device, chain.Installation, chain.Session, chain.CallerInstance, []));
        Assert.Throws<ArgumentException>(() => new ActorChain(chain.Owner, default, chain.Installation, chain.Session, chain.CallerInstance, []));
        Assert.Throws<ArgumentException>(() => new ActorChain(chain.Owner, chain.Device, default, chain.Session, chain.CallerInstance, []));
        Assert.Throws<ArgumentException>(() => new ActorChain(chain.Owner, chain.Device, chain.Installation, default, chain.CallerInstance, []));
        Assert.Throws<ArgumentException>(() => new ActorChain(chain.Owner, chain.Device, chain.Installation, chain.Session, default, []));
        Assert.Throws<ArgumentNullException>(() => new ActorChain(chain.Owner, chain.Device, chain.Installation, chain.Session, chain.CallerInstance, null!));
    }

    [Fact]
    public void HumanOwnerAndExecutorAreDistinctAndSequenceIsDefensivelyCopied()
    {
        var chain = Create();
        var actors = chain.Actors.ToArray();
        var copied = new ActorChain(chain.Owner, chain.Device, chain.Installation, chain.Session, chain.CallerInstance, actors);
        actors[0] = Actor(ActorKind.Extension);
        Assert.Equal(ActorKind.Automation, copied.Actors[0].Kind);
        Assert.Equal(chain.Owner, copied.Owner);
        Assert.NotEqual(copied.CallerInstance, copied.Actors[0].Executor);
        Assert.Throws<NotSupportedException>(() => ((IList<DelegatedActor>)copied.Actors).Clear());
    }

    [Fact]
    public void DirectHumanOperationMayHaveNoDelegates()
    {
        var chain = Create();
        var direct = new ActorChain(chain.Owner, chain.Device, chain.Installation, chain.Session, chain.CallerInstance, []);
        Assert.Empty(ActorChainSnapshot.Decode(ActorChainSnapshot.Encode(direct)).Chain.Actors);
    }

    [Fact]
    public void RejectsUnknownKindsDefaultIdsDuplicatesAndOverlongChains()
    {
        var chain = Create();
        Assert.Throws<ArgumentException>(() => new HumanPrincipal(chain.Owner.Realm, default, HumanIdentityKind.CloudUser));
        Assert.Throws<ArgumentException>(() => new HumanPrincipal(default, chain.Owner.Id, HumanIdentityKind.CloudUser));
        Assert.NotEqual(chain.Owner, new HumanPrincipal(new RealmId(Guid.NewGuid()), chain.Owner.Id, chain.Owner.Kind));
        Assert.Throws<ArgumentOutOfRangeException>(() => new HumanPrincipal(chain.Owner.Realm, chain.Owner.Id, (HumanIdentityKind)99));
        Assert.Throws<ArgumentOutOfRangeException>(() => Actor((ActorKind)99));
        Assert.Throws<ArgumentException>(() => new DelegatedActor(ActorKind.Agent, Guid.Empty, chain.CallerInstance, "software"));
        Assert.Throws<ArgumentException>(() => new DelegatedActor(ActorKind.Agent, Guid.NewGuid(), default, "software"));
        Assert.Throws<ArgumentException>(() => new DelegatedActor(ActorKind.Agent, Guid.NewGuid(), chain.CallerInstance, "\n"));
        Assert.Throws<ArgumentException>(() => new ActorChain(chain.Owner, chain.Device, chain.Installation, chain.Session, chain.CallerInstance, [chain.Actors[0], chain.Actors[0]]));
        Assert.Throws<ArgumentException>(() => new ActorChain(chain.Owner, chain.Device, chain.Installation, chain.Session, chain.CallerInstance, Enumerable.Range(0, 33).Select(_ => Actor(ActorKind.Agent))));
    }

    [Theory]
    [InlineData("realm")]
    [InlineData("owner")]
    [InlineData("humanKind")]
    [InlineData("device")]
    [InlineData("installation")]
    [InlineData("session")]
    [InlineData("callerInstance")]
    [InlineData("actors")]
    [InlineData("actorCount")]
    public void BoundaryRefusesEveryMissingIdentityField(string field)
    {
        var node = JsonNode.Parse(ActorChainSnapshot.Encode(Create()))!.AsObject();
        Assert.True(node.Remove(field));
        Assert.Throws<JsonException>(() => ActorChainSnapshot.Decode(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Fact]
    public void BoundaryRejectsTruncationDuplicateFieldsUnknownVersionAndUnknownKinds()
    {
        var bytes = ActorChainSnapshot.Encode(Create());
        Assert.ThrowsAny<JsonException>(() => ActorChainSnapshot.Decode(bytes.AsSpan(0, bytes.Length - 1)));
        Assert.Throws<JsonException>(() => ActorChainSnapshot.Decode(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace("\"version\":1", "\"version\":1,\"version\":1", StringComparison.Ordinal))));
        var node = JsonNode.Parse(bytes)!.AsObject();
        node["version"] = 2;
        Assert.Throws<JsonException>(() => ActorChainSnapshot.Decode(Encoding.UTF8.GetBytes(node.ToJsonString())));
        node["version"] = 1;
        node["actors"]!.AsArray().RemoveAt(0);
        Assert.Throws<JsonException>(() => ActorChainSnapshot.Decode(Encoding.UTF8.GetBytes(node.ToJsonString())));
        node["actorCount"] = 3;
        node["actors"]![0]!["kind"] = 99;
        Assert.Throws<ArgumentOutOfRangeException>(() => ActorChainSnapshot.Decode(Encoding.UTF8.GetBytes(node.ToJsonString())));
        Assert.Throws<ArgumentException>(() => ActorChainSnapshot.Decode(new byte[ActorChainSnapshot.MaximumBytes + 1]));
    }
    [Fact]
    public void SoftwareIdentityIsLosslessUnicodeAndRejectsMalformedUtf16()
    {
        var chain = Create();
        foreach (var malformed in new[] { "\ud800", "\udfff", "a\ud800z" })
        {
            Assert.Throws<EncoderFallbackException>(() => new DelegatedActor(ActorKind.Agent, Guid.NewGuid(), chain.CallerInstance, malformed));
        }

        var actor = new DelegatedActor(ActorKind.Agent, Guid.NewGuid(), chain.CallerInstance, "software/\ud83d\ude00");
        var unicode = new ActorChain(chain.Owner, chain.Device, chain.Installation, chain.Session, chain.CallerInstance, [actor]);
        Assert.Equal(actor, ActorChainSnapshot.Decode(ActorChainSnapshot.Encode(unicode)).Chain.Actors[0]);
    }

    [Theory]
    [InlineData("kind")]
    [InlineData("actor")]
    [InlineData("executor")]
    [InlineData("software")]
    public void BoundaryRejectsIncompleteDelegate(string field)
    {
        var node = JsonNode.Parse(ActorChainSnapshot.Encode(Create()))!;
        Assert.True(node["actors"]![0]!.AsObject().Remove(field));
        Assert.Throws<JsonException>(() => ActorChainSnapshot.Decode(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Fact]
    public void ForgedOwnerRemainsUntrustedAfterReserialization()
    {
        var original = Create();
        var node = JsonNode.Parse(ActorChainSnapshot.Encode(original))!;
        var forgedOwner = Guid.NewGuid();
        node["owner"] = forgedOwner;
        var evidence = ActorChainSnapshot.Decode(Encoding.UTF8.GetBytes(node.ToJsonString()));
        Assert.Equal(forgedOwner, evidence.Chain.Owner.Id.Value);
        Assert.NotEqual(original.Owner, evidence.Chain.Owner);
        var forwarded = ActorChainSnapshot.Decode(ActorChainSnapshot.Encode(evidence.Chain));
        Assert.IsType<UntrustedActorChainEvidence>(forwarded);
        Assert.Equal(evidence.Chain.Owner, forwarded.Chain.Owner);
        // No serialized assertion can upgrade evidence to an authenticated identity.
        node["trusted"] = true;
        Assert.Throws<JsonException>(() => ActorChainSnapshot.Decode(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Fact]
    public void BoundaryRejectsEmptyIdsRepeatedActorsAndInvalidSoftware()
    {
        var node = JsonNode.Parse(ActorChainSnapshot.Encode(Create()))!;
        node["owner"] = Guid.Empty;
        Assert.Throws<ArgumentException>(() => ActorChainSnapshot.Decode(Encoding.UTF8.GetBytes(node.ToJsonString())));
        node["owner"] = Guid.NewGuid();
        node["actors"]![1] = node["actors"]![0]!.DeepClone();
        Assert.Throws<ArgumentException>(() => ActorChainSnapshot.Decode(Encoding.UTF8.GetBytes(node.ToJsonString())));
        node["actors"]![1]!["actor"] = Guid.NewGuid();
        node["actors"]![0]!["software"] = new string('x', 257);
        Assert.Throws<ArgumentException>(() => ActorChainSnapshot.Decode(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }}
