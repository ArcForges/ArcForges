// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using Xunit;

namespace ArcForges.Tests.ContractSchemaTests;

public sealed class LocalRpcGoldenShapeTests
{
    private static readonly Lazy<string> GoldenRoot = new(LocateGoldenRoot);
    private static readonly Lazy<string> ManifestPath = new(LocateManifestPath);

    [Fact]
    [Trait("Category", "Contract")]
    public void EveryLocalRpcGoldenFileIsValidJson()
    {
        var goldenFiles = Directory.EnumerateFiles(GoldenRoot.Value, "*.json").ToArray();
        Assert.True(goldenFiles.Length >= 18, $"Expected >= 18 golden files, found {goldenFiles.Length}");

        foreach (var file in goldenFiles)
        {
            var content = File.ReadAllText(file);
            using var doc = JsonDocument.Parse(content);
            Assert.NotEqual(JsonValueKind.Undefined, doc.RootElement.ValueKind);
        }
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void RegisterInstanceRequestShapeMatchesContract()
    {
        using var doc = ReadGolden("register-instance-request");
        var root = doc.RootElement;

        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        Assert.True(root.TryGetProperty("product", out var product));
        Assert.Equal("arcnotes", product.GetString());

        Assert.True(root.TryGetProperty("instance", out _));
        Assert.True(root.TryGetProperty("processId", out var pid));
        Assert.Equal(1234, pid.GetInt32());

        Assert.True(root.TryGetProperty("transport", out var transport));
        Assert.Equal("namedpipe", transport.GetString());

        Assert.True(root.TryGetProperty("capabilities", out var caps));
        Assert.Equal(JsonValueKind.Array, caps.ValueKind);
        Assert.True(caps.GetArrayLength() > 0);
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void InsertBlocksRequestShapeMatchesMutationEnvelope()
    {
        using var doc = ReadGolden("insert-blocks-request");
        var root = doc.RootElement;

        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        Assert.True(root.TryGetProperty("commandId", out _));
        Assert.True(root.TryGetProperty("actor", out var actor));
        Assert.Equal(JsonValueKind.Object, actor.ValueKind);
        Assert.True(actor.TryGetProperty("actorChain", out _));
        Assert.True(actor.TryGetProperty("correlation", out _));

        Assert.True(root.TryGetProperty("targetResource", out _));
        Assert.True(root.TryGetProperty("expectedRevision", out var expectedRev));
        Assert.Equal(1, expectedRev.GetInt64());

        Assert.True(root.TryGetProperty("issuedAtUtc", out _));
        Assert.True(root.TryGetProperty("deadlineUtc", out _));
        Assert.True(root.TryGetProperty("correlationId", out _));
        Assert.True(root.TryGetProperty("blocks", out var blocks));
        Assert.Equal(JsonValueKind.Array, blocks.ValueKind);
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void HeartbeatRequestShapeMatchesContract()
    {
        using var doc = ReadGolden("heartbeat-request");
        var root = doc.RootElement;

        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        Assert.True(root.TryGetProperty("instance", out _));
        Assert.True(root.TryGetProperty("sessionToken", out _));
        Assert.True(root.TryGetProperty("health", out var health));
        Assert.True(health.ValueKind is JsonValueKind.Number or JsonValueKind.String);
        Assert.True(root.TryGetProperty("activeDocuments", out _));
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void RequestApprovalRequestShapeMatchesContract()
    {
        using var doc = ReadGolden("request-approval-request");
        var root = doc.RootElement;

        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        Assert.True(root.TryGetProperty("command", out _));
        Assert.True(root.TryGetProperty("task", out _));
        Assert.True(root.TryGetProperty("targetResource", out _));
        Assert.True(root.TryGetProperty("proposedEffect", out _));
        Assert.True(root.TryGetProperty("riskClass", out var risk));
        Assert.Equal("R1", risk.GetString());
        Assert.True(root.TryGetProperty("expiresAtUtc", out _));
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void LocalRpcManifestConformsToSchema()
    {
        Assert.True(File.Exists(ManifestPath.Value), "Manifest must exist at artifacts/contracts/localrpc-contracts.v1.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(ManifestPath.Value));
        var root = doc.RootElement;

        Assert.Equal("1.0.0", root.GetProperty("schemaVersion").GetString());
        Assert.Equal("localrpc.v1", root.GetProperty("contractSet").GetString());

        var interfaces = root.GetProperty("interfaces");
        string[] expectedInterfaces = ["ILocalHubControlRpc", "IArcNotesRpcV1", "IArcScopeRpcV1", "IArcSlateRpcV1"];

        var totalMethods = 0;
        string[] validRisks = ["R0", "R1", "R2", "R3", "R4"];

        foreach (var expected in expectedInterfaces)
        {
            Assert.True(interfaces.TryGetProperty(expected, out var ifaceElem), $"Missing interface {expected}");
            var methods = ifaceElem.GetProperty("methods");
            totalMethods += methods.GetArrayLength();

            foreach (var m in methods.EnumerateArray())
            {
                Assert.True(m.TryGetProperty("name", out var name) && !string.IsNullOrEmpty(name.GetString()));
                Assert.True(m.TryGetProperty("request", out var req) && !string.IsNullOrEmpty(req.GetString()));
                Assert.True(m.TryGetProperty("response", out var res) && !string.IsNullOrEmpty(res.GetString()));
                Assert.True(m.TryGetProperty("capability", out var cap) && !string.IsNullOrEmpty(cap.GetString()));
                Assert.True(m.TryGetProperty("risk", out var risk) && validRisks.Contains(risk.GetString()));

                var flags = m.GetProperty("flags");
                Assert.True(flags.GetProperty("read").ValueKind is JsonValueKind.True or JsonValueKind.False);
                Assert.True(flags.GetProperty("write").ValueKind is JsonValueKind.True or JsonValueKind.False);
                Assert.True(flags.GetProperty("cancellable").ValueKind is JsonValueKind.True or JsonValueKind.False);
            }
        }

        Assert.Equal(96, totalMethods);
    }

    private static JsonDocument ReadGolden(string name)
    {
        var path = Path.Combine(GoldenRoot.Value, name + ".json");
        return JsonDocument.Parse(File.ReadAllText(path));
    }

    private static string LocateRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ArcForges.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    private static string LocateGoldenRoot() =>
        Path.Combine(LocateRepoRoot(), "tests", "ContractCompatibilityTests", "golden", "localrpc", "v1");

    private static string LocateManifestPath()
    {
        var repoRoot = LocateRepoRoot();
        var p1 = Path.Combine(repoRoot, "contracts", "localrpc", "v1", "localrpc-contracts.v1.json");
        if (File.Exists(p1))
        {
            return p1;
        }

        return Path.Combine(repoRoot, "artifacts", "contracts", "localrpc-contracts.v1.json");
    }
}
