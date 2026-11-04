// SPDX-License-Identifier: AGPL-3.0-only
using System.Numerics;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// N1-22: the node's own client against a REAL center (a center on real PostgreSQL: the local official-hosted rehearsal, or proof with the
/// coordinator's go), with anonymous calls only: nothing here needs an approval or an account. The real C# client, HTTP seam, file-backed
/// node key and proof builder; a PollDeviceAuthorization answered PENDING is the cross-language evidence that the node's proof (purpose
/// 0x02: the preimage, the audience digest, P1363 and low-S) verifies with the Go center's verifier, which answers every failed proof
/// AUTHENTICATION/unauthenticated. Purpose 0x01 shares every field before its binding and is checked end to end by part N2's closed loop.
/// Skipped with its reason unless ARCFORGES_E2E_CENTER_URL names the center (it is never run against production).
/// </summary>
[Trait("loop", "cloud")]
public sealed class CenterProtocolProbeTests
{
    private const string Variable = "ARCFORGES_E2E_CENTER_URL";

    [Fact]
    public async Task TheRealCenterVerifiesTheNodesProofAndMatchesTheDerivedUrls()
    {
        var url = Environment.GetEnvironmentVariable(Variable);
        Assert.SkipUnless(!string.IsNullOrEmpty(url), Variable + " is not set");
        Assert.True(CenterEndpoint.TryParse(url, out var center, out var reason), reason);
        Assert.NotEqual(CenterEndpoint.OfficialDefault, center.Url);
        var root = Directory.CreateTempSubdirectory("arcforges-probe-").FullName;
        try
        {
            var nodeId = RandomNumberGenerator.GetBytes(16);
            using var key = NodeKeyStores.ForTestDataRoot(root).Create(nodeId, center.Origin, TimeProvider.System);
            using var http = new CenterHttpClient(center);
            var client = new CenterClient(http, TimeProvider.System);
            var ct = TestContext.Current.CancellationToken;
            var node = new EnrollingNodeInfo
            {
                NodeId = new Id { Value = ByteString.CopyFrom(nodeId) },
                Name = "n1-probe-" + Convert.ToHexStringLower(nodeId)[..8],
                Os = OperatingSystem.IsWindows() ? OsFamily.Windows : OsFamily.Linux,
                Arch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.Arm64
                    ? CpuArchitecture.Arm64 : CpuArchitecture.X64,
                Version = NodeContract.ProductVersion,
                Role = NodeRole.Host,
            };

            // StartDeviceAuthorization: the center's URLs equal the ones the node derives from its configured center.
            var start = await client.StartDeviceAuthorizationAsync(new NodeEnrollmentServiceStartDeviceAuthorizationRequest
            {
                Node = node,
                NodePublicKey = ByteString.CopyFrom(key.PublicKey),
            }, ct);
            Assert.True(start.Outcome == CenterOutcome.Value, start.Detail + " " + start.Code);
            var authorization = start.Value!.Authorization;
            Assert.Equal(center.ActivateUrl, authorization.VerificationUri);
            Assert.Equal(center.ActivateCompleteUrl(authorization.UserCode), authorization.VerificationUriComplete);

            var message = CloudIdentity.ProofMessage(CloudIdentity.PurposePoll, center, nodeId, CloudIdentity.PollBinding(authorization.DeviceCode));
            var proof = key.Sign(message);
            Assert.True(CloudIdentity.IsLowS(proof));

            // The high-S twin of the node's proof and a proof for another audience are refused like any failed proof.
            var order = BigInteger.Parse("0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture);
            var high = proof.ToArray();
            Array.Clear(high, 32, 32);
            (order - new BigInteger(proof.AsSpan(32), isUnsigned: true, isBigEndian: true)).ToByteArray(isUnsigned: true, isBigEndian: true).CopyTo(high.AsSpan(64 - 32));
            foreach (var refused in new[]
            {
                high,
                key.Sign(CloudIdentity.ProofMessage(CloudIdentity.PurposePoll, CenterEndpoint.Parse(center.Url + "/other"), nodeId,
                    CloudIdentity.PollBinding(authorization.DeviceCode))),
            })
            {
                var bad = await client.PollDeviceAuthorizationAsync(new NodeEnrollmentServicePollDeviceAuthorizationRequest
                {
                    DeviceCode = authorization.DeviceCode,
                    NodeKeyProof = ByteString.CopyFrom(refused),
                }, ct);
                Assert.Equal("AUTHENTICATION/unauthenticated", bad.Code);
            }

            // The node's own proof verifies: the authorization is PENDING (it was never approved).
            var poll = await client.PollDeviceAuthorizationAsync(new NodeEnrollmentServicePollDeviceAuthorizationRequest
            {
                DeviceCode = authorization.DeviceCode,
                NodeKeyProof = ByteString.CopyFrom(proof),
            }, ct);
            Assert.True(poll.Outcome == CenterOutcome.Value, poll.Detail + " " + poll.Code);
            Assert.Equal(DeviceAuthorizationState.Pending, poll.Value!.State);

            // BeginNodeSignIn: authorize_url is the derived /connect#flow= string (RFC 9562 form of the flow ID's bytes).
            var verifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var challenge = Convert.ToBase64String(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var begin = await client.BeginNodeSignInAsync(new NodeEnrollmentServiceBeginNodeSignInRequest
            {
                CodeChallenge = challenge,
                RedirectUri = "http://127.0.0.1:" + RandomNumberGenerator.GetInt32(20000, 60000) + "/callback",
                Node = node,
                State = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).Replace('+', '-').Replace('/', '_'),
                NodePublicKey = ByteString.CopyFrom(key.PublicKey),
            }, ct);
            Assert.True(begin.Outcome == CenterOutcome.Value, begin.Detail + " " + begin.Code);
            Assert.Equal(center.ConnectUrl(begin.Value!.FlowId.Value.Span), begin.Value.AuthorizeUrl);

            // The refusal shapes the node maps: an unknown refresh token is a domain refusal; an unknown bearer an ingress refusal.
            var refresh = await client.RefreshAsync("afr1." + new string('A', 43), ct);
            Assert.Equal("AUTHENTICATION/unauthenticated", refresh.Code);
            var report = await client.ReportNodeInfoAsync("afa1." + new string('A', 43), node, CommandIds.New(), ct);
            Assert.Equal(CenterOutcome.Transport, report.Outcome);
            Assert.Equal("auth.unauthenticated", report.TransportCode);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
