// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;
using WireDecimal = ArcForges.Contracts.Foundation.V1.Decimal;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual 450.1 published Decimal shape and the local Fleet response consumer.</summary>
public sealed class OptionalAvailableDecimalTests
{
    [Theory]
    [InlineData(null, true)]
    [InlineData("1.00", true)]
    [InlineData("0.0", true)]
    [InlineData("-1.00", true)]
    [InlineData("0.000000000", true)]
    [InlineData("0.000000001", true)]
    [InlineData("9999999999999999999999999999", true)]
    [InlineData("", false)]
    [InlineData("01.0", false)]
    [InlineData("-0.0", false)]
    [InlineData("+1", false)]
    [InlineData("1.", false)]
    [InlineData("0.0000000001", false)]
    [InlineData("99999999999999999999999999999", false)]
    public void AvailableMatchesPublishedShapeAndOriginalPlanResponse(string? available, bool valid)
    {
        var target = CommandIds.New();
        var meta = Tasks.Meta();
        var request = new FileServicePlanRemovalRequest
        {
            Meta = meta.Clone(),
            WorkspacePath = new FilePath { WorkspaceId = CommandIds.New(), Path = "tree" },
        };
        var limit = new LimitFailure
        {
            LimitName = "removal_ownership_input_bytes",
            Maximum = new WireDecimal { Value = "67108864" },
            Available = available is null ? null : new WireDecimal { Value = available },
        };
        var inner = new FileServicePlanRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Error = new ArcError
            {
                Category = ErrorCategory.Resource,
                Code = "too_large",
                MessageKey = "error.resource.too_large",
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                Effect = EffectCertainty.DidNotHappen,
                CorrelationId = meta.CorrelationId.Clone(),
                Details = new ErrorDetails { Limit = limit },
            },
        };
        var raw = inner.ToByteString();
        var outer = new FleetServicePlanNodeRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServicePlanNodeRemovalValue { NodeId = target, Response = raw },
        };
        if (available is not null) Assert.Equal(valid, NodeShapes.IsValid(limit.Available));
        Assert.Equal(valid, NodeShapes.IsValid(inner));
        Assert.Equal(valid, RoutedFileResponseValidation.PlanRemoval(outer, target, request));
        Assert.Equal(raw, outer.Value.Response); // Validation must not normalize the signed inner bytes.
    }

    [Fact]
    public void AvailableWithoutValueIsInvalidAndMaximumStillHasTheStricterProfile()
    {
        var target = CommandIds.New();
        var meta = Tasks.Meta();
        var request = new FileServicePlanRemovalRequest
        {
            Meta = meta.Clone(),
            WorkspacePath = new FilePath { WorkspaceId = CommandIds.New(), Path = "tree" },
        };
        var limit = new LimitFailure
        {
            LimitName = "removal_ownership_input_bytes",
            Maximum = new WireDecimal { Value = "67108864" },
            Available = new WireDecimal(),
        };
        var inner = new FileServicePlanRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Error = new ArcError
            {
                Category = ErrorCategory.Resource,
                Code = "too_large",
                MessageKey = "error.resource.too_large",
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                Effect = EffectCertainty.DidNotHappen,
                CorrelationId = meta.CorrelationId.Clone(),
                Details = new ErrorDetails { Limit = limit },
            },
        };
        var outer = new FleetServicePlanNodeRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServicePlanNodeRemovalValue { NodeId = target },
        };
        bool Accept()
        {
            outer.Value.Response = inner.ToByteString();
            return RoutedFileResponseValidation.PlanRemoval(outer, target, request);
        }
        Assert.False(NodeShapes.IsValid(inner));
        Assert.False(Accept());
        limit.Available.Value = "1.00";
        limit.Maximum.Value = "67108864.00";
        Assert.True(NodeShapes.IsValid(inner));
        Assert.False(Accept());
        limit.Maximum.Value = "067108864";
        Assert.False(NodeShapes.IsValid(inner));
        Assert.False(Accept());
        limit.Maximum.Value = "67108864";
        limit.LimitName = "opaque.64m";
        Assert.True(NodeShapes.IsValid(inner));
        Assert.True(Accept());
    }
}
