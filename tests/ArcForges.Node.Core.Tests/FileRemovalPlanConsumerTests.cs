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

/// <summary>Published 450.1 shape and local routed consumer checks; not actual Center validation.</summary>
public sealed class FileRemovalPlanConsumerTests
{
    [Fact]
    public void UnownedPlanRequiresApprovalAndBindsNodeTargetAndExactTotals()
    {
        var target = CommandIds.New();
        var meta = Tasks.Meta();
        var path = new FilePath { WorkspaceId = CommandIds.New(), Path = "tree" };
        var request = new FileServicePlanRemovalRequest { Meta = meta.Clone(), WorkspacePath = path.Clone() };
        var plan = new FileRemovalPlan
        {
            PlanId = CommandIds.New(),
            Digest = ByteString.CopyFrom(SHA256.HashData("plan"u8)),
            ExpiresAt = ProtoTime.ToInstant(DateTimeOffset.UtcNow.AddMinutes(60)),
            WorkspacePath = path.Clone(),
            TotalBytes = 3,
            RequiresApproval = true,
            QuarantineAvailable = false,
            Risk = RiskClass.High,
            Items =
            {
                new FileRemovalItem { Path = "tree", Kind = FileEntryKind.Directory, SizeBytes = 0,
                    IdentitySha256 = ByteString.CopyFrom(SHA256.HashData("root"u8)), OwnerVerified = false },
                new FileRemovalItem { Path = "tree/file", Kind = FileEntryKind.File, SizeBytes = 3,
                    IdentitySha256 = ByteString.CopyFrom(SHA256.HashData("file"u8)), OwnerVerified = false },
            },
        };
        var inner = new FileServicePlanRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FileServicePlanRemovalValue { Plan = plan },
        };
        var response = new FleetServicePlanNodeRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServicePlanNodeRemovalValue { NodeId = target.Clone(), Response = inner.ToByteString() },
        };
        Assert.True(NodeShapes.IsValid(inner));
        Assert.True(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        response.Value.NodeId = CommandIds.New();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        response.Value.NodeId = target.Clone();
        plan.RequiresApproval = false;
        response.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        plan.RequiresApproval = true;
        plan.TotalBytes = 4;
        response.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        plan.TotalBytes = 3;
        plan.Items[1].Path = "other/file";
        response.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(response, target, request));
    }

    [Fact]
    public void LimitsAreCanonicalAndOpaqueNamesMustMatchARealApplicableBound()
    {
        var target = CommandIds.New();
        var meta = Tasks.Meta();
        var request = new FileServicePlanRemovalRequest
        {
            Meta = meta.Clone(),
            WorkspacePath = new FilePath { WorkspaceId = CommandIds.New(), Path = "tree" },
        };
        var error = new ArcError
        {
            Category = ErrorCategory.Resource,
            Code = "too_large",
            MessageKey = "error.resource.too_large",
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            Effect = EffectCertainty.DidNotHappen,
            CorrelationId = meta.CorrelationId.Clone(),
            Details = new ErrorDetails { Limit = new LimitFailure { LimitName = "removal_descendants", Maximum = new WireDecimal { Value = "1000" } } },
        };
        var inner = new FileServicePlanRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Error = error,
        };
        var response = new FleetServicePlanNodeRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServicePlanNodeRemovalValue { NodeId = target.Clone(), Response = inner.ToByteString() },
        };
        Assert.True(NodeShapes.IsValid(inner));
        Assert.True(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        error.Details.Limit.LimitName = "another.valid.limit";
        response.Value.Response = inner.ToByteString();
        Assert.True(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        error.Details.Limit.Maximum.Value = "1000.00";
        Assert.True(NodeShapes.IsValid(error));
        response.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        error.Details.Limit.Maximum.Value = "1000";
        error.Details.Limit.LimitName = "file_write_bytes";
        response.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        error.Details.Limit.LimitName = "path_bytes";
        error.Details.Limit.Maximum.Value = "4096";
        response.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(response, target, request));
    }
}
