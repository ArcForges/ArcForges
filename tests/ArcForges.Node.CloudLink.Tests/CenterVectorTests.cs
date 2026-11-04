// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N1-1 and N1-12 against the center's own vector lists (protocol-4 item 3, node-13; N1 decisions R-2, G-4): the two files Cloud's
/// <c>TestFleetVectorFiles</c> generates from the production functions (<c>config.ParsePublicBaseURL</c>, the fleet center's configuration
/// loader, <c>fleet.ProofMessage</c>, <c>fleet.VerifyNodeKeyProof</c>, <c>fleet.Fingerprint</c>), vendored byte for byte from Cloud 41c8a72
/// (#136) with a manifest. Cross-language: the Go center's verdicts and bytes against the node's C# builders, fingerprint and URL rules,
/// and against FakeCenter's C# verifier. The keys are fixed test-only keys, never a node's.
/// </summary>
public sealed class CenterVectorTests
{
    private static readonly string Directory_ = Path.Combine(AppContext.BaseDirectory, "Fixtures", "center-vectors");

    [Fact]
    public void TheVectorFilesAreTheCentersBytes()
    {
        FakeCenterConformanceTests.VendoredManifest("center-vectors", 2);
        Assert.Equal("6f4e8cd4551b3823f50cd0ea2e9d6245b4c13b199f0f0eeedc22f500b2320d72", Sha(Path.Combine(Directory_, "url-vectors.json")));
        Assert.Equal("02c4300986818cae2fce3c2657025e52738a6f6802cfe6c91dec35b3fafdec2d", Sha(Path.Combine(Directory_, "node-key-proof-vectors.json")));
    }

    [Fact]
    public void TheNodeAcceptsACenterUrlExactlyAsTheCenterDoesWithinItsBound()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Directory_, "url-vectors.json")));
        var root = document.RootElement;
        var flow = Convert.FromHexString(root.GetProperty("flowId").GetString()!);
        var userCode = root.GetProperty("userCode").GetString()!;
        Assert.Equal(CenterEndpoint.FleetBaseMaxLength, root.GetProperty("maxFleetPublicBaseUrlLength").GetInt32());
        var checkedDerived = 0;
        var vectors = root.GetProperty("baseUrls").EnumerateArray().ToList();
        Assert.True(vectors.Count >= 40);
        foreach (var vector in vectors)
        {
            var input = vector.GetProperty("input").GetString()!;
            var name = vector.GetProperty("name").GetString();
            var selfHosted = vector.GetProperty("selfHosted");
            var centerAccepts = selfHosted.GetProperty("publicBaseUrl").GetProperty("accepted").GetBoolean();
            var fleetAccepts = selfHosted.GetProperty("fleetCenter").GetProperty("accepted").GetBoolean()
                || vector.GetProperty("officialHosted").GetProperty("fleetCenter").GetProperty("accepted").GetBoolean();

            // The node's rule: the center's canonical form (self-hosted mode, the wider one) within the contract's 512 characters; every URL a
            // fleet center accepts is one the node accepts, as written.
            var nodeAccepts = CenterEndpoint.TryParse(input, out var endpoint, out var reason);
            Assert.True(nodeAccepts == (centerAccepts && input.Length <= CenterEndpoint.MaxLength), $"{name}: {input} node {nodeAccepts} ({reason})");
            Assert.False(fleetAccepts && !nodeAccepts, name);
            if (!nodeAccepts)
            {
                continue;
            }

            Assert.Equal(input, endpoint!.Url);
            Assert.Equal(input.Length > CenterEndpoint.FleetBaseMaxLength, endpoint.ExceedsFleetBase);
            if (vector.TryGetProperty("derived", out var derived))
            {
                Assert.Equal(derived.GetProperty("authorizeUrl").GetString(), endpoint.ConnectUrl(flow));
                Assert.Equal(derived.GetProperty("verificationUri").GetString(), endpoint.ActivateUrl);
                Assert.Equal(derived.GetProperty("verificationUriComplete").GetString(), endpoint.ActivateCompleteUrl(userCode));
                Assert.Equal(derived.GetProperty("proofAudienceSha256").GetString(), Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(endpoint.Url))));
                checkedDerived++;
            }
        }

        Assert.True(checkedDerived >= 7);
    }

    [Fact]
    public void TheNodesFingerprintIsTheCentersAndOnlyP256PkixKeysVerify()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Directory_, "node-key-proof-vectors.json")));
        var keys = document.RootElement.GetProperty("keys").EnumerateArray().ToList();
        Assert.Equal(6, keys.Count);
        foreach (var key in keys)
        {
            var spki = Convert.FromHexString(key.GetProperty("spki").GetString()!);
            if (key.GetProperty("validNodeKey").GetBoolean())
            {
                Assert.Equal(CloudIdentity.PublicKeyLength, spki.Length);
                Assert.Equal(key.GetProperty("fingerprint").GetString(), CloudIdentity.Fingerprint(spki));
                Assert.EndsWith("-" + key.GetProperty("fingerprintTail").GetString(), CloudIdentity.Fingerprint(spki), StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void TheNodeBuildsTheCentersProofMessagesAndAgreesWithEveryVerdict()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Directory_, "node-key-proof-vectors.json")));
        var root = document.RootElement;
        Assert.Equal(root.GetProperty("domainHex").GetString(), Convert.ToHexStringLower(Encoding.ASCII.GetBytes(CloudIdentity.ProofDomain)));
        var keys = root.GetProperty("keys").EnumerateArray().ToDictionary(key => key.GetProperty("name").GetString()!,
            key => Convert.FromHexString(key.GetProperty("spki").GetString()!), StringComparer.Ordinal);
        var proofs = root.GetProperty("proofs").EnumerateArray().ToList();
        Assert.Equal(31, proofs.Count);
        var accepted = new List<(byte[] Message, byte[] Proof)>();
        var built = 0;
        foreach (var vector in proofs)
        {
            var name = vector.GetProperty("name").GetString()!;
            var message = Convert.FromHexString(vector.GetProperty("message").GetString()!);
            var proof = Convert.FromHexString(vector.GetProperty("proof").GetString()!);
            var verdict = vector.GetProperty("accepted").GetBoolean();
            if (!vector.TryGetProperty("messageConstruction", out _))
            {
                // message = ProofMessage(purpose, audience, nodeId, binding): the node's builder makes the same bytes from the same inputs.
                var purpose = (byte)vector.GetProperty("purpose").GetInt32();
                var audience = vector.GetProperty("audience").GetString()!;
                var nodeId = Convert.FromHexString(vector.GetProperty("nodeId").GetString()!);
                var binding = purpose == CloudIdentity.PurposeComplete
                    ? CloudIdentity.CompleteBinding(Convert.FromHexString(vector.GetProperty("flowId").GetString()!), vector.GetProperty("code").GetString()!)
                    : CloudIdentity.PollBinding(vector.GetProperty("deviceCode").GetString()!);
                Assert.Equal(vector.GetProperty("binding").GetString(), Convert.ToHexStringLower(binding));
                Assert.Equal(vector.GetProperty("audienceSha256").GetString(), Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(audience))));
                if (CenterEndpoint.TryParse(audience, out var center, out _))
                {
                    Assert.Equal(message, CloudIdentity.ProofMessage(purpose, center, nodeId, binding));
                    built++;
                }
                else
                {
                    // An audience the node cannot be configured with (a trailing slash): the node never signs for it; refused by the center.
                    Assert.False(verdict, name);
                }
            }

            // FakeCenter's C# verifier gives the Go center's verdict for every vector.
            Assert.True(verdict == FakeCenter.VerifyNodeKeyProof(keys[vector.GetProperty("nodeKey").GetString()!], message, proof), name);
            if (verdict)
            {
                Assert.True(CloudIdentity.IsLowS(proof), name);
                Assert.Equal(proof, CloudIdentity.NormalizeLowS(proof));
                accepted.Add((message, proof));
            }
        }

        Assert.True(built >= 20);
        Assert.Contains(proofs, vector => vector.TryGetProperty("leadingZero", out var zero) && zero.GetString() == "r" && vector.GetProperty("accepted").GetBoolean());
        Assert.Contains(proofs, vector => vector.TryGetProperty("leadingZero", out var zero) && zero.GetString() == "s" && vector.GetProperty("accepted").GetBoolean());

        // The node's normalization turns the refused high-S twin into the center's accepted proof of the same message.
        var twin = proofs.Single(vector => vector.GetProperty("name").GetString()!.Contains("high-S twin", StringComparison.Ordinal));
        var twinMessage = Convert.FromHexString(twin.GetProperty("message").GetString()!);
        var normalized = CloudIdentity.NormalizeLowS(Convert.FromHexString(twin.GetProperty("proof").GetString()!));
        Assert.Contains(accepted, item => item.Message.SequenceEqual(twinMessage) && item.Proof.SequenceEqual(normalized));
    }

    private static string Sha(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
}
