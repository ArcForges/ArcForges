// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed class RoutedRemovalExecutionResponseTests
{
    [Theory]
    [InlineData("removal_descendants", "1000", true)]
    [InlineData("removal_total_bytes", "67108864", true)]
    [InlineData("removal_ownership_input_bytes", "67108864", false)]
    [InlineData("removal_plan_response_bytes", "1040384", false)]
    [InlineData("opaque_limit", "67108864", true)]
    [InlineData("opaque_limit", "1000", true)]
    [InlineData("opaque_limit", "1000.5", false)]
    [InlineData("opaque_limit", "01000", false)]
    [InlineData("path_bytes", "4096", false)]
    public void RemovalLimitsUseOnlyTheExecutionMethodBounds(string name, string maximum, bool accepted)
    {
        var request = new FileServiceExecuteRemovalRequest
        {
            Meta = Tasks.Meta(),
            PlanId = CommandIds.New(),
            PlanDigest = ByteString.CopyFrom(new byte[32]),
        };
        var target = CommandIds.New();
        var inner = new FileServiceExecuteRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Error = new ArcError
            {
                Category = ErrorCategory.Resource,
                Code = "too_large",
                MessageKey = "error.resource.too_large",
                CorrelationId = request.Meta.CorrelationId.Clone(),
                Effect = EffectCertainty.DidNotHappen,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                Details = new ErrorDetails
                {
                    Limit = new LimitFailure { LimitName = name, Maximum = new ArcForges.Contracts.Foundation.V1.Decimal { Value = maximum } },
                },
            },
        };
        var response = new FleetServiceExecuteNodeRemovalResponse
        {
            Value = new FleetServiceExecuteNodeRemovalValue { NodeId = target.Clone(), Response = inner.ToByteString() },
        };
        Assert.Equal(accepted, RoutedFileResponseValidation.ExecuteRemoval(response, target, request));
        response.Value.NodeId = CommandIds.New();
        Assert.False(RoutedFileResponseValidation.ExecuteRemoval(response, target, request));
    }

    [Fact]
    public void ARemovalResultMustBindTheRequestedPlanAndItsQuarantineChoice()
    {
        var request = new FileServiceExecuteRemovalRequest
        {
            Meta = Tasks.Meta(),
            PlanId = CommandIds.New(),
            PlanDigest = ByteString.CopyFrom(new byte[32]),
        };
        var target = CommandIds.New();
        var result = new FileRemovalResult
        {
            PlanId = request.PlanId.Clone(),
            Quarantined = false,
            ItemsRemoved = 1,
            TotalBytes = 8,
        };
        var inner = new FileServiceExecuteRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Value = new FileServiceExecuteRemovalValue { Result = result },
        };
        bool Check() => RoutedFileResponseValidation.ExecuteRemoval(new FleetServiceExecuteNodeRemovalResponse
        {
            Value = new FleetServiceExecuteNodeRemovalValue { NodeId = target.Clone(), Response = inner.ToByteString() },
        }, target, request);
        Assert.False(Check());
        request.DeleteWithoutQuarantine = true;
        Assert.True(Check()); // Consumer shape only: no cleanup or HUMAN approval is simulated as real.
        result.PlanId = CommandIds.New();
        Assert.False(Check());
        result.PlanId = request.PlanId.Clone();
        result.Quarantined = true;
        Assert.False(Check());
        result.QuarantineId = CommandIds.New();
        result.PurgeAfter = ProtoTime.ToInstant(DateTimeOffset.UtcNow.AddDays(1));
        Assert.True(Check()); // A metadata consumer cannot prove elapsed retention.
        result.ItemsRemoved = 1002;
        Assert.False(Check());
    }
}
