// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Sandbox.V2;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

public sealed class RemoteManagementV2WireTests
{
    private const uint FrameLimit = 4096;
    private const long Deadline = 1780000000000L;
    private const string Binding = "3701dce54ed2deef91eb714b0fb51df87bc918a6ce4f8a65a91f5ca6999b0253";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(Deadline - 1);
    private static ReadOnlySpan<byte> RequestBody => [0x0a, 0x02, 0x0a, 0x00];
    private static ReadOnlySpan<byte> ResultBody => [0x12, 0x00];

    [Fact]
    public void SharedGoldenVectorPreservesExactMetadataBodiesAndByteOrder()
    {
        var header = Header();
        var prepared = Assert.IsType<V2ControlPreparedFrame>(V2ControlWire.PrepareRequest(header, RequestBody, 3, FrameLimit, Now));
        var signature = InertSignature();
        var frame = Assert.IsType<byte[]>(prepared.AttachSignature(signature));
        Assert.Equal("02070000000000000003", Convert.ToHexStringLower(frame.AsSpan(0, 10)));
        Assert.Equal("18e679c4a39177c99326ff11a1f12118443d06689993850147a3c89faa5b79ce", Sha(frame));
        Assert.Equal(Binding, Sha(prepared.SigningInput.Span));
        Assert.Equal(Binding, Convert.ToHexStringLower(prepared.RequestBinding.Span));
        Assert.False(V2ChannelProtocol.TryDecode(frame, 3, out _));
        Assert.True(V2ChannelProtocol.TryDecode(frame, 3, out var liveFrame, controlEnabled: true));
        Assert.Equal(V2ChannelKind.ControlRequest, liveFrame.Kind);
        Assert.True(V2ControlWire.TryDecodeRequest(frame, 3, (uint)frame.Length, Now, out var request));
        Assert.Equal(header.Selector, request.Header.Selector);
        Assert.Equal(header.KeyId, request.Header.KeyId);
        Assert.Equal(header.GrantRevision, request.Header.GrantRevision);
        Assert.Equal(header.HubFence, request.Header.HubFence);
        Assert.Equal(Deadline, request.Header.DeadlineUnixMilliseconds);
        Assert.Equal(RepeatId(0x88), request.Header.OriginalOwnerEpoch.ToArray());
        Assert.Equal(RepeatId(0x99), request.Header.CommandId.ToArray());
        Assert.Equal(RequestBody.ToArray(), request.Body.ToArray());
        Assert.Equal(signature, request.Signature.ToArray());
        Assert.Equal(prepared.SigningInput.ToArray(), request.SigningInput.ToArray());

        var response = Assert.IsType<V2ControlPreparedFrame>(
            V2ControlWire.PrepareResult(request.Header.CallId.Span, request.RequestBinding.Span, ResultBody, 9, FrameLimit));
        var resultFrame = Assert.IsType<byte[]>(response.AttachSignature(signature));
        Assert.Equal("02080000000000000009", Convert.ToHexStringLower(resultFrame.AsSpan(0, 10)));
        Assert.Equal("d27efbd9ce723c7e19cb1dde666d9f8f60945a0ca77487f2b2e760347b7ce063", Sha(resultFrame));
        Assert.Equal("ebe5152f7615826cf8c3b1c6b33f405962e296b2108e90893d6be421105f895a", Sha(response.SigningInput.Span));
        var liveResponse = Assert.IsType<V2ControlPreparedFrame>(
            V2ControlWire.PrepareResultPayload(request.Header.CallId.Span, request.RequestBinding.Span, ResultBody, FrameLimit));
        var livePayload = Assert.IsType<byte[]>(liveResponse.AttachPayloadSignature(signature));
        Assert.Equal(resultFrame, V2ChannelProtocol.Encode(V2ChannelKind.ControlResult, 9, livePayload));
        Assert.True(V2ControlWire.TryDecodeResult(resultFrame, 9, (uint)resultFrame.Length, out var result));
        Assert.Equal(header.CallId.ToArray(), result.CallId.ToArray());
        Assert.Equal(Binding, Convert.ToHexStringLower(result.RequestBinding.Span));
        Assert.Equal(ResultBody.ToArray(), result.Body.ToArray());
        Assert.Equal(signature, result.Signature.ToArray());
        Assert.Equal(response.SigningInput.ToArray(), result.SigningInput.ToArray());
    }

    [Fact]
    public void DetachedSignaturesUseTheExistingP256VerificationAndSeparateDomains()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = key.ExportSubjectPublicKeyInfo();
        var request = Assert.IsType<V2ControlPreparedFrame>(V2ControlWire.PrepareRequest(Header(), RequestBody, 3, FrameLimit, Now));
        var result = Assert.IsType<V2ControlPreparedFrame>(
            V2ControlWire.PrepareResult(RepeatId(0x11), request.RequestBinding.Span, ResultBody, 9, FrameLimit));
        var requestSignature = Sign(key, request.SigningInput.Span);
        var resultSignature = Sign(key, result.SigningInput.Span);
        var requestFrame = Assert.IsType<byte[]>(request.AttachSignature(requestSignature));
        var resultFrame = Assert.IsType<byte[]>(result.AttachSignature(resultSignature));
        Assert.True(V2ControlWire.TryDecodeRequest(requestFrame, 3, FrameLimit, Now, out var decodedRequest));
        Assert.True(V2ControlWire.TryDecodeResult(resultFrame, 9, FrameLimit, out var decodedResult));
        Assert.True(RelaySignatures.Verify(publicKey, decodedRequest.SigningInput.Span, decodedRequest.Signature.Span));
        Assert.True(RelaySignatures.Verify(publicKey, decodedResult.SigningInput.Span, decodedResult.Signature.Span));
        Assert.False(RelaySignatures.Verify(publicKey, decodedResult.SigningInput.Span, decodedRequest.Signature.Span));
        Assert.Null(request.AttachSignature(new byte[63]));
    }

    [Theory]
    [InlineData((int)V2ControlSelector.NodeGetOperation, true)]
    [InlineData((int)V2ControlSelector.NodeListRemoteGrants, false)]
    [InlineData((int)V2ControlSelector.NodeRevokeRemoteGrant, true)]
    [InlineData((int)V2ControlSelector.SandboxCreate, true)]
    [InlineData((int)V2ControlSelector.SandboxConfigure, true)]
    [InlineData((int)V2ControlSelector.SandboxList, false)]
    [InlineData((int)V2ControlSelector.SandboxInspect, false)]
    [InlineData((int)V2ControlSelector.RunStart, true)]
    [InlineData((int)V2ControlSelector.RunStop, true)]
    [InlineData((int)V2ControlSelector.RunList, false)]
    [InlineData((int)V2ControlSelector.RunInspect, false)]
    [InlineData((int)V2ControlSelector.ResourceGetBudget, false)]
    [InlineData((int)V2ControlSelector.ResourceSetPolicy, true)]
    public void OnlyFixedSelectorsAdmitTheExpectedCommandBinding(int selectorNumber, bool hasCommand)
    {
        var selector = (V2ControlSelector)selectorNumber;
        var valid = Header() with { Selector = selector, CommandId = hasCommand ? RepeatId(0x99) : new byte[16] };
        var invalid = valid with { CommandId = hasCommand ? new byte[16] : RepeatId(0x99) };
        var prepared = Assert.IsType<V2ControlPreparedFrame>(V2ControlWire.PrepareRequest(valid, RequestBody, 3, FrameLimit, Now));
        var frame = Assert.IsType<byte[]>(prepared.AttachSignature(InertSignature()));
        Assert.True(V2ControlWire.TryDecodeRequest(frame, 3, FrameLimit, Now, out var decoded));
        Assert.Equal((byte)selector, frame[26]);
        Assert.Equal(valid.CommandId.ToArray(), decoded.Header.CommandId.ToArray());
        Assert.Null(V2ControlWire.PrepareRequest(invalid, RequestBody, 3, FrameLimit, Now));
    }

    [Fact]
    public void RejectsOutOfBoundsFramesAndMalformedShapeBeforeReturningBodies()
    {
        var header = Header();
        var prepared = Assert.IsType<V2ControlPreparedFrame>(V2ControlWire.PrepareRequest(header, RequestBody, 3, FrameLimit, Now));
        var frame = Assert.IsType<byte[]>(prepared.AttachSignature(InertSignature()));
        Assert.False(V2ControlWire.TryDecodeRequest(frame, 4, FrameLimit, Now, out _));
        Assert.False(V2ControlWire.TryDecodeRequest(frame, 3, (uint)frame.Length - 1, Now, out _));
        Assert.False(V2ControlWire.TryDecodeRequest(frame.AsMemory(0, frame.Length - 1), 3, FrameLimit, Now, out _));
        Assert.False(V2ControlWire.TryDecodeRequest(frame, 3, FrameLimit, DateTimeOffset.FromUnixTimeMilliseconds(Deadline), out _));
        Assert.Null(V2ControlWire.PrepareRequest(header with { DeadlineUnixMilliseconds = 0 }, RequestBody, 3, FrameLimit, Now));
        Assert.NotNull(V2ControlWire.PrepareRequest(header with { DeadlineUnixMilliseconds = long.MaxValue }, RequestBody, 3, FrameLimit, Now));
        Assert.Null(V2ControlWire.PrepareRequest(header, RequestBody, 3, (uint)frame.Length - 1, Now));
        Assert.Null(V2ControlWire.PrepareRequest(header, [], 3, FrameLimit, Now));
        Assert.Null(V2ControlWire.PrepareRequest(header with { GrantRevision = 0 }, RequestBody, 3, FrameLimit, Now));
        Assert.Null(V2ControlWire.PrepareRequest(header with { HubFence = ulong.MaxValue }, RequestBody, 3, FrameLimit, Now));
        Assert.Null(V2ControlWire.PrepareRequest(header with { ActorId = new byte[16] }, RequestBody, 3, FrameLimit, Now));
        Assert.Null(V2ControlWire.PrepareRequest(header with { KeyId = "key.invalid/" }, RequestBody, 3, FrameLimit, Now));
        Assert.Null(V2ControlWire.PrepareRequest(header with { KeyId = new string('k', 65) }, RequestBody, 3, FrameLimit, Now));
        Assert.Null(V2ControlWire.PrepareRequest(header with { Selector = (V2ControlSelector)14 }, RequestBody, 3, FrameLimit, Now));
        var unknownSelector = (byte[])frame.Clone();
        unknownSelector[26] = 14;
        Assert.False(V2ControlWire.TryDecodeRequest(unknownSelector, 3, FrameLimit, Now, out _));
        var wrongRequestDigest = (byte[])frame.Clone();
        wrongRequestDigest[227] ^= 1;
        Assert.False(V2ControlWire.TryDecodeRequest(wrongRequestDigest, 3, FrameLimit, Now, out _));

        var response = Assert.IsType<V2ControlPreparedFrame>(
            V2ControlWire.PrepareResult(header.CallId.Span, prepared.RequestBinding.Span, ResultBody, 9, FrameLimit));
        var result = Assert.IsType<byte[]>(response.AttachSignature(InertSignature()));
        Assert.False(V2ControlWire.TryDecodeResult(result, 0, FrameLimit, out _));
        Assert.False(V2ControlWire.TryDecodeResult(result, 9, (uint)result.Length - 1, out _));
        Assert.False(V2ControlWire.TryDecodeResult(result.AsMemory(0, result.Length - 1), 9, FrameLimit, out _));
        Assert.False(V2ControlWire.TryDecodeResult(frame, 3, FrameLimit, out _));
        result[62] ^= 1;
        Assert.False(V2ControlWire.TryDecodeResult(result, 9, FrameLimit, out _));
    }

    private static V2ControlRequestHeader Header() => new(
        RepeatId(0x11), V2ControlSelector.RunStart, RepeatId(0x22), RepeatId(0x33), RepeatId(0x44), RepeatId(0x55),
        RepeatId(0x66), RepeatId(0x77), RepeatId(0x88), RepeatId(0x99), RepeatId(0xaa), 0x0102030405060708UL, 19,
        Deadline, SHA256.HashData("https://center.example.test/managed"u8), "relay.fixture-1");

    private static byte[] RepeatId(byte value) => [.. Enumerable.Repeat(value, 16)];

    private static byte[] InertSignature()
    {
        var signature = new byte[64];
        signature[31] = 1;
        signature[63] = 2;
        return signature;
    }

    private static byte[] Sign(ECDsa key, ReadOnlySpan<byte> input) =>
        CloudIdentity.NormalizeLowS(key.SignData(input, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    private static string Sha(ReadOnlySpan<byte> input) => Convert.ToHexStringLower(SHA256.HashData(input));

    [Theory]
    [InlineData(14, false,
        "126d9abbf208582a45af1a64831f3d508accafad031a28b0193fbdf43f17cec0",
        "bb4a129c0297685688cc1547dcc549b83438ce91b071e55c720a8cb7d5e97c79",
        "8c3a206c07f116b8f39d5e3a54b21c30eb006df8c710eb5ed6aadbe4c502b5bf",
        "c6cf764758ba96b0d060bc991f2549c7af324828681d6b64a5e131490ba3f6a3")]
    [InlineData(18, true,
        "f1df16e94a6af0236165eaad1c48ea4467b5c36cc476e0149c743ea8404f6319",
        "98825bf4f44e3207968563b8ea7c4854cb97adce6c095b92cc571caf9c000d1b",
        "0d6a92fda4dc338186c9c6aced5a5fc00a5223b0397d3d5d0acd657076fbba5f",
        "4f767da3383510e52f4f58fcd42d68a72f3b2ce4464fac99d77846f168a3bc5e")]
    public void NegotiatedWatchAndDataMatchIndependentGoVectors(int selectorNumber, bool data, string binding, string signedResult,
        string requestFrameHash, string resultFrameHash)
    {
        var selector = (V2ControlSelector)selectorNumber;
        var header = Header() with { Selector = selector, CommandId = data ? RepeatId(0x99) : new byte[16] };
        Assert.Null(V2ControlWire.PrepareRequest(header, RequestBody, 3, FrameLimit, Now));
        var request = Assert.IsType<V2ControlPreparedFrame>(V2ControlWire.PrepareRequest(header, RequestBody, 3, FrameLimit, Now,
            streamDataEnabled: true));
        var frame = Assert.IsType<byte[]>(request.AttachSignature(InertSignature()));
        Assert.Equal(data ? (byte)9 : (byte)7, frame[1]);
        Assert.Equal(requestFrameHash, Sha(frame));
        Assert.Equal(binding, Convert.ToHexStringLower(request.RequestBinding.Span));
        Assert.False(V2ControlWire.TryDecodeRequest(frame, 3, FrameLimit, Now, out _));
        Assert.True(V2ControlWire.TryDecodeRequest(frame, 3, FrameLimit, Now, out var decoded, streamDataEnabled: true));
        Assert.Equal(selector, decoded.Header.Selector);

        byte[] body = data ? ResultBody.ToArray() : [1, .. ResultBody];
        var result = Assert.IsType<V2ControlPreparedFrame>(V2ControlWire.PrepareResult(header.CallId.Span, decoded.RequestBinding.Span,
            body, 9, FrameLimit, selector, streamDataEnabled: true));
        var resultFrame = Assert.IsType<byte[]>(result.AttachSignature(InertSignature()));
        Assert.Equal(data ? (byte)10 : (byte)8, resultFrame[1]);
        Assert.Equal(resultFrameHash, Sha(resultFrame));
        Assert.Equal(signedResult, Sha(result.SigningInput.Span));
        Assert.True(V2ControlWire.TryDecodeResult(resultFrame, 9, FrameLimit, out var decodedResult, selector, streamDataEnabled: true));
        Assert.Equal(body, decodedResult.Body.ToArray());
    }

    [Fact]
    public void OnlyTheSelectedDataDirectionCarriesAFullPublishedChunk()
    {
        const uint legacy = CenterChannelClient.MaxFrameBytes;
        var chunk = ByteString.CopyFrom(new byte[CenterChannelClient.MaxFrameBytes]);
        var writeBody = new DataServiceWriteImportRequest { Chunk = chunk }.ToByteArray();
        var readBody = new DataServiceReadExportResponse { Value = new() { Chunk = new() { Data = chunk } } }.ToByteArray();
        Assert.True(writeBody.Length > legacy);
        Assert.True(readBody.Length > legacy);
        Assert.Equal(V2ControlWire.DataBodyLimit, V2ControlWire.MaximumResponseBodyBytes(V2ControlSelector.DataReadExport, legacy));
        Assert.Equal((int)legacy - 158, V2ControlWire.MaximumResponseBodyBytes(V2ControlSelector.DataWriteImport, legacy));

        var header = Header() with { Selector = V2ControlSelector.DataWriteImport };
        var upload = Assert.IsType<V2ControlPreparedFrame>(
            V2ControlWire.PrepareRequest(header, writeBody, 3, legacy, Now, streamDataEnabled: true));
        var uploadFrame = Assert.IsType<byte[]>(upload.AttachSignature(InertSignature()));
        Assert.False(V2ControlWire.IsLargeWritePrefix(uploadFrame.AsSpan(0, V2ControlWire.RequestPrefixBytes - 1), 3));
        Assert.True(V2ControlWire.IsLargeWritePrefix(uploadFrame.AsSpan(0, V2ControlWire.RequestPrefixBytes), 3));
        Assert.False(V2ControlWire.IsLargeWritePrefix(uploadFrame, 4));
        Assert.False(V2ChannelProtocol.TryDecode(uploadFrame, 3, out _, controlEnabled: true));
        Assert.True(V2ChannelProtocol.TryDecode(uploadFrame, 3, out var uploadKind, streamDataEnabled: true));
        Assert.Equal(V2ChannelKind.DataRequest, uploadKind.Kind);
        Assert.False(V2ControlWire.TryDecodeRequest(uploadFrame, 3, legacy, Now, out _));
        Assert.True(V2ControlWire.TryDecodeRequest(uploadFrame, 3, legacy, Now, out var parsed, streamDataEnabled: true));
        Assert.Equal(writeBody, parsed.Body.ToArray());
        Assert.Null(V2ControlWire.PrepareRequest(header with { Selector = V2ControlSelector.DataBeginImport },
            writeBody, 3, legacy, Now, streamDataEnabled: true));
        Assert.Null(V2ControlWire.PrepareRequest(header, new byte[V2ControlWire.DataBodyLimit + 1],
            3, legacy, Now, streamDataEnabled: true));

        var download = Assert.IsType<V2ControlPreparedFrame>(V2ControlWire.PrepareResult(header.CallId.Span,
            parsed.RequestBinding.Span, readBody, 9, legacy, V2ControlSelector.DataReadExport, streamDataEnabled: true));
        var downloadFrame = Assert.IsType<byte[]>(download.AttachSignature(InertSignature()));
        Assert.False(V2ControlWire.TryDecodeResult(downloadFrame, 9, legacy, out _, V2ControlSelector.DataWriteImport, streamDataEnabled: true));
        Assert.True(V2ControlWire.TryDecodeResult(downloadFrame, 9, legacy, out var decodedResult, V2ControlSelector.DataReadExport,
            streamDataEnabled: true));
        Assert.Equal(readBody, decodedResult.Body.ToArray());
        Assert.Null(V2ControlWire.PrepareResult(header.CallId.Span, parsed.RequestBinding.Span, readBody, 9, legacy,
            V2ControlSelector.DataInspectTransfer, streamDataEnabled: true));
    }

    [Fact]
    public void WatchIdleAndTypedFrameMarkersHaveExactShapes()
    {
        var header = Header();
        var binding = Convert.FromHexString(Binding);
        var selector = V2ControlSelector.ResourceWatchUsage;
        Assert.Equal((int)FrameLimit - 159, V2ControlWire.MaximumResponseBodyBytes(selector, FrameLimit));
        Assert.NotNull(V2ControlWire.PrepareResult(header.CallId.Span, binding, [0], 9, FrameLimit, selector, streamDataEnabled: true));
        Assert.NotNull(V2ControlWire.PrepareResult(header.CallId.Span, binding, [1, .. ResultBody], 9, FrameLimit, selector, streamDataEnabled: true));
        Assert.Null(V2ControlWire.PrepareResult(header.CallId.Span, binding, [1], 9, FrameLimit, selector, streamDataEnabled: true));
        Assert.Null(V2ControlWire.PrepareResult(header.CallId.Span, binding, [0, .. ResultBody], 9, FrameLimit, selector, streamDataEnabled: true));
        Assert.Null(V2ControlWire.PrepareResult(header.CallId.Span, binding, [2, .. ResultBody], 9, FrameLimit, selector, streamDataEnabled: true));
    }
}
