// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;
using WireDecimal = ArcForges.Contracts.Foundation.V1.Decimal;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual 450.1 consumer shape and additional read-reply binding checks.</summary>
public sealed class RoutedFileResponseValidationTests
{
    [Theory]
    [InlineData("0")]
    [InlineData("-0.1")]
    [InlineData("4096")]
    [InlineData("4194304")]
    [InlineData("123.456")]
    [InlineData("1234567890123456789012345678")]
    public void CanonicalValuesRemainAccepted(string value) =>
        Assert.True(RoutedFileResponseValidation.CanonicalDecimal(new WireDecimal { Value = value }));

    [Theory]
    [InlineData("")]
    [InlineData("-0")]
    [InlineData("01")]
    [InlineData(".1")]
    [InlineData("1.")]
    [InlineData("1.0")]
    [InlineData("4194304.00")]
    [InlineData("1.234567890")]
    [InlineData("1.2.3")]
    [InlineData("12345678901234567890123456789")]
    public void NoncanonicalValuesAreRejectedEvenIfTheSdkAcceptsThem(string value) =>
        Assert.False(RoutedFileResponseValidation.CanonicalDecimal(new WireDecimal { Value = value }));

    [Fact]
    public void TheActual450ConsumerGapDoesNotPassTheProductBoundary()
    {
        var error = TooLarge("file_existing_bytes", "4194304.00");
        Assert.True(NodeShapes.IsValid(error));
        Assert.False(RoutedFileResponseValidation.CanonicalLimits(error));
        error.Details.Limit.Maximum.Value = "4194304";
        Assert.True(NodeShapes.IsValid(error));
        Assert.True(RoutedFileResponseValidation.CanonicalLimits(error));
    }

    [Fact]
    public void ReadLimitNamesAreOpenButKnownMethodAndRequestFactsStillBindThem()
    {
        var target = CommandIds.New();
        var request = Request(new string('x', 4097));
        var response = new FleetServiceReadNodeFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = CommandIds.New() },
            Error = TooLarge("another_path_limit", "4096"),
        };
        Assert.True(RoutedFileResponseValidation.Read(response, target, request));
        response.Error.Details.Limit.LimitName = "workspace_root_path_bytes";
        Assert.False(RoutedFileResponseValidation.Read(response, target, request));
        response.Error.Details.Limit.LimitName = "path_bytes";
        response.Error.Details.Limit.Maximum.Value = "4096.00";
        Assert.True(NodeShapes.IsValid(response.Error));
        Assert.False(RoutedFileResponseValidation.Read(response, target, request));
        response.Error.Details.Limit.Maximum.Value = "4096";
        request.Path.Path = "short";
        Assert.False(RoutedFileResponseValidation.Read(response, target, request));
    }

    [Fact]
    public void AReadResponseBindsTheTargetBytesContinuationAndAudit()
    {
        var target = CommandIds.New();
        var request = Request("file");
        var data = ByteString.CopyFrom([1, 2, 3]);
        var hash = ByteString.CopyFrom(SHA256.HashData(data.Span));
        var inner = new FileServiceReadFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = CommandIds.New() },
            Value = new FileServiceReadFileValue { Data = data, Offset = 0, NextOffset = 3, Eof = true, FileSize = 3, Sha256 = hash },
            Audit = new FileAuditMetadata
            {
                Observations = { new FileAuditObservation { Kind = FileAuditKind.ReadBytes, SizeBytes = 3, DigestInputBytes = 3, Sha256 = hash } },
            },
        };
        var response = new FleetServiceReadNodeFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = CommandIds.New() },
            Value = new FleetServiceReadNodeFileValue { NodeId = target.Clone(), Response = inner.ToByteString() },
        };
        Assert.True(RoutedFileResponseValidation.Read(response, target, request));
        response.Value.NodeId = CommandIds.New();
        Assert.False(RoutedFileResponseValidation.Read(response, target, request));
        response.Value.NodeId = target.Clone();
        inner.Value.NextOffset = 2;
        response.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.Read(response, target, request));
        inner.Value.NextOffset = 3;
        inner.Audit.Observations[0].Sha256 = ByteString.CopyFrom(new byte[32]);
        response.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.Read(response, target, request));
    }

    private static ArcError TooLarge(string name, string maximum) => new()
    {
        Category = ErrorCategory.Resource,
        Code = "too_large",
        MessageKey = "error.resource.too_large",
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Effect = EffectCertainty.DidNotHappen,
        CorrelationId = CommandIds.New(),
        Details = new ErrorDetails { Limit = new LimitFailure { LimitName = name, Maximum = new WireDecimal { Value = maximum } } },
    };

    private static FileServiceReadFileRequest Request(string path) => new()
    {
        Path = new FilePath { WorkspaceId = CommandIds.New(), Path = path },
        Offset = 0,
        Length = 3,
    };
}
