// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Published 450.1 and local Fleet consumer shapes; this does not assert a real Center call.</summary>
public sealed class AttemptRemovalPlanConsumerTests
{
    [Fact]
    public void AttemptRootAndChildrenRetainAttemptTargetAndPublishedShape()
    {
        var target = CommandIds.New();
        var meta = Tasks.Meta();
        var attempt = CommandIds.New();
        var request = new FileServicePlanRemovalRequest { Meta = meta.Clone(), AttemptId = attempt.Clone() };
        var plan = new FileRemovalPlan
        {
            PlanId = CommandIds.New(),
            Digest = ByteString.CopyFrom(SHA256.HashData("attempt-plan"u8)),
            ExpiresAt = ProtoTime.ToInstant(DateTimeOffset.UtcNow.AddMinutes(60)),
            AttemptId = attempt.Clone(),
            TotalBytes = 3,
            RequiresApproval = true,
            QuarantineAvailable = false,
            Risk = RiskClass.High,
            Items =
            {
                new FileRemovalItem { Path = "", Kind = FileEntryKind.Directory, SizeBytes = 0,
                    IdentitySha256 = ByteString.CopyFrom(SHA256.HashData("attempt-root"u8)), OwnerVerified = true },
                new FileRemovalItem { Path = "sub", Kind = FileEntryKind.Directory, SizeBytes = 0,
                    IdentitySha256 = ByteString.CopyFrom(SHA256.HashData("attempt-sub"u8)), OwnerVerified = false },
                new FileRemovalItem { Path = "sub/file", Kind = FileEntryKind.File, SizeBytes = 3,
                    IdentitySha256 = ByteString.CopyFrom(SHA256.HashData("attempt-file"u8)), OwnerVerified = false },
            },
        };
        var inner = new FileServicePlanRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FileServicePlanRemovalValue { Plan = plan },
        };
        var outer = new FleetServicePlanNodeRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServicePlanNodeRemovalValue { NodeId = target.Clone(), Response = inner.ToByteString() },
        };
        Assert.True(NodeShapes.IsValid(request));
        Assert.True(NodeShapes.IsValid(inner));
        Assert.True(RoutedFileResponseValidation.PlanRemoval(outer, target, request));
        plan.AttemptId = CommandIds.New();
        outer.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(outer, target, request));
        plan.AttemptId = attempt.Clone();
        plan.Items[0].Path = "not-the-attempt-root";
        outer.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(outer, target, request));
        plan.Items[0].Path = "";
        plan.Items[0].Kind = FileEntryKind.File;
        outer.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(outer, target, request));
        plan.Items[0].Kind = FileEntryKind.Directory;
        plan.Items[2].Path = "elsewhere/file";
        outer.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(outer, target, request));
    }

    [Fact]
    public void UnavailableAttemptTempUsesCallerNamedAttemptIdInPublishedShape()
    {
        var target = CommandIds.New();
        var meta = Tasks.Meta();
        var attempt = CommandIds.New();
        var request = new FileServicePlanRemovalRequest { Meta = meta.Clone(), AttemptId = attempt.Clone() };
        var error = new ArcError
        {
            Category = ErrorCategory.State,
            Code = "not_found",
            MessageKey = "error.state.not_found",
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            Effect = EffectCertainty.DidNotHappen,
            CorrelationId = meta.CorrelationId.Clone(),
            Details = new ErrorDetails
            {
                State = new StateFailure
                {
                    State = "attempt_temp",
                    Reason = "not_found",
                    Resource = new AggregateRef { Kind = "attempt_temp", Id = attempt.Clone() },
                },
            },
        };
        var inner = new FileServicePlanRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Error = error,
        };
        var outer = new FleetServicePlanNodeRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServicePlanNodeRemovalValue { NodeId = target.Clone(), Response = inner.ToByteString() },
        };
        Assert.True(NodeShapes.IsValid(inner));
        Assert.True(RoutedFileResponseValidation.PlanRemoval(outer, target, request));
    }

}
