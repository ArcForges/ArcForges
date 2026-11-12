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
        var outerTreeObservation = new FleetServicePlanNodeRemovalResponse { Meta = response.Meta.Clone(), Error = error.Clone() };
        Assert.False(RoutedFileResponseValidation.PlanRemoval(outerTreeObservation, target, request));
        error.Details.Limit.LimitName = "another.valid.limit";
        response.Value.Response = inner.ToByteString();
        Assert.True(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        outerTreeObservation.Error = error.Clone();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(outerTreeObservation, target, request));
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
        error.Details.Limit.LimitName = "removal_plan_response_bytes";
        error.Details.Limit.Maximum.Value = "1040384";
        response.Value.Response = inner.ToByteString();
        Assert.True(NodeShapes.IsValid(inner));
        Assert.True(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        var attempt = new FileServicePlanRemovalRequest { Meta = meta.Clone(), AttemptId = CommandIds.New() };
        Assert.True(NodeShapes.IsValid(attempt));
        Assert.True(RoutedFileResponseValidation.PlanRemoval(response, target, attempt));
        var outer = new FleetServicePlanNodeRemovalResponse { Meta = response.Meta.Clone(), Error = error.Clone() };
        Assert.False(RoutedFileResponseValidation.PlanRemoval(outer, target, request));
        error.Details.Limit.LimitName = "opaque.plan.budget";
        response.Value.Response = inner.ToByteString();
        Assert.True(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        outer.Error = error.Clone();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(outer, target, request));
        error.Details.Limit.LimitName = "removal_descendants";
        response.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        error.Details.Limit.LimitName = "removal_plan_response_bytes";
        error.Details.Limit.Maximum.Value = "1040383";
        response.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        error.Details.Limit.Maximum.Value = "1040384.00";
        Assert.True(NodeShapes.IsValid(error));
        response.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(response, target, request));
        error.Details.Limit.Maximum.Value = "1040384";
        error.Details.Limit.LimitName = "bad name";
        response.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(response, target, request));
    }
    [Fact]
    public void PlanInputObservationAndLimitAreMethodScopedAndPreserveOpenNames()
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
            Details = new ErrorDetails
            {
                Limit = new LimitFailure { LimitName = "removal_ownership_input_bytes", Maximum = new WireDecimal { Value = "67108864" } },
            },
        };
        var observation = new FileAuditObservation
        {
            Kind = FileAuditKind.InputBytes,
            SizeBytes = 67_108_864,
            DigestInputBytes = 67_108_864,
            Sha256 = ByteString.CopyFrom(SHA256.HashData("shape-only"u8)),
        };
        var inner = new FileServicePlanRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Error = error,
            Audit = new FileAuditMetadata { Observations = { observation } },
        };
        var response = new FleetServicePlanNodeRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServicePlanNodeRemovalValue { NodeId = target.Clone(), Response = inner.ToByteString() },
        };
        bool Accept()
        {
            response.Value.Response = inner.ToByteString();
            return RoutedFileResponseValidation.PlanRemoval(response, target, request);
        }
        Assert.True(NodeShapes.IsValid(inner));
        Assert.True(Accept());
        error.Details.Limit.LimitName = "opaque.budget";
        Assert.True(Accept()); // Both 64 MiB node-observed bounds remain possible.
        error.Details.Limit.LimitName = "removal_ownership_input_bytes";
        error.Details.Limit.Maximum.Value = "67108864.00";
        Assert.True(NodeShapes.IsValid(inner)); // Published generic shape permits fractional trailing zeroes.
        Assert.False(Accept()); // The AF-CTR-06 limit profile requires exact integer text.
        error.Details.Limit.Maximum.Value = "067108864";
        Assert.False(NodeShapes.IsValid(inner));
        Assert.False(Accept());
        error.Details.Limit.Maximum.Value = "67108864";
        var outer = new FleetServicePlanNodeRemovalResponse { Meta = response.Meta.Clone(), Error = error.Clone() };
        Assert.False(RoutedFileResponseValidation.PlanRemoval(outer, target, request));

        observation.SizeBytes = 0;
        observation.DigestInputBytes = 0;
        Assert.False(Accept());
        observation.SizeBytes = 67_108_865;
        observation.DigestInputBytes = 67_108_865;
        Assert.False(Accept());
        observation.SizeBytes = 1;
        observation.DigestInputBytes = 2;
        Assert.False(Accept());
        observation.DigestInputBytes = 1;
        observation.ItemCount = 1;
        Assert.False(Accept());
        observation.ClearItemCount();
        observation.Sha256 = ByteString.CopyFrom(new byte[31]);
        Assert.False(Accept());
        observation.Sha256 = ByteString.CopyFrom(SHA256.HashData("shape-only"u8));
        observation.Kind = FileAuditKind.OperationMetadata;
        Assert.False(Accept());
        observation.Kind = FileAuditKind.InputBytes;
        inner.Audit.Observations.Add(observation.Clone());
        Assert.False(Accept());
        inner.Audit.Observations.RemoveAt(1);
        Assert.True(Accept());
    }

    [Fact]
    public void CompleteResponseBudgetIncludesMetaTargetItemsAndAnyPopulatedAudit()
    {
        const int maximum = 1_040_384;
        var target = CommandIds.New();
        var meta = Tasks.Meta();
        var selected = new FilePath { WorkspaceId = CommandIds.New(), Path = "tree" };
        var request = new FileServicePlanRemovalRequest { Meta = meta.Clone(), WorkspacePath = selected.Clone() };
        var plan = new FileRemovalPlan
        {
            PlanId = CommandIds.New(),
            Digest = ByteString.CopyFrom(SHA256.HashData("exact-plan"u8)),
            ExpiresAt = ProtoTime.ToInstant(DateTimeOffset.UtcNow.AddMinutes(60)),
            WorkspacePath = selected.Clone(),
            TotalBytes = 1,
            RequiresApproval = true,
            QuarantineAvailable = false,
            Risk = RiskClass.High,
        };
        static FileRemovalItem Item(string path, FileEntryKind kind) => new()
        {
            Path = path,
            Kind = kind,
            SizeBytes = 0,
            IdentitySha256 = ByteString.CopyFrom(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(path))),
            OwnerVerified = false,
        };
        var prefix = selected.Path;
        plan.Items.Add(Item(prefix, FileEntryKind.Directory));
        for (var depth = 0; depth < 5; depth++)
        {
            prefix += "/" + new string((char)('a' + depth), 210);
            plan.Items.Add(Item(prefix, FileEntryKind.Directory));
        }
        for (var index = 0; index < 920; index++)
            plan.Items.Add(Item(prefix + "/f" + index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture), FileEntryKind.File));
        plan.Items[^1].SizeBytes = 1;
        plan.Items[^1].OwnerVerified = true;
        var response = new FileServicePlanRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FileServicePlanRemovalValue { Plan = plan },
            Audit = new FileAuditMetadata
            {
                Observations = { new FileAuditObservation { Kind = FileAuditKind.InputBytes, SizeBytes = 1,
                    DigestInputBytes = 1, Sha256 = ByteString.CopyFrom(SHA256.HashData("x"u8)) } },
            },
        };
        var missing = maximum - response.CalculateSize();
        Assert.InRange(missing, 0, 920 * 240);
        foreach (var item in plan.Items.Skip(6))
        {
            var extra = Math.Min(missing, 240);
            item.Path += new string('x', extra);
            missing -= extra;
        }
        Assert.Equal(0, missing);
        Assert.Equal(maximum, response.CalculateSize());
        Assert.Equal(maximum, response.ToByteArray().Length);
        Assert.True(NodeShapes.IsValid(plan));
        Assert.All(plan.Items, item => Assert.True(NodeShapes.IsValid(item)));
        Assert.True(NodeShapes.IsValid(response));
        Assert.True(FileServiceHandler.RemovalPlanResponseFits(response));
        var outer = new FleetServicePlanNodeRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServicePlanNodeRemovalValue { NodeId = target.Clone(), Response = response.ToByteString() },
        };
        Assert.True(RoutedFileResponseValidation.PlanRemoval(outer, target, request));

        var withAudit = response.Clone();
        withAudit.Audit.Observations.Add(new FileAuditObservation
        {
            Kind = FileAuditKind.ReadBytes,
            SizeBytes = 0,
            DigestInputBytes = 0,
            Sha256 = ByteString.CopyFrom(SHA256.HashData([]))
        });
        Assert.True(NodeShapes.IsValid(withAudit.Audit));
        Assert.True(withAudit.CalculateSize() > maximum);
        Assert.False(FileServiceHandler.RemovalPlanResponseFits(withAudit));
        var withMeta = response.Clone();
        withMeta.Meta.Warnings.Add("x");
        Assert.True(withMeta.CalculateSize() > maximum);
        Assert.False(FileServiceHandler.RemovalPlanResponseFits(withMeta));

        plan.Items[^1].Path += "x";
        Assert.Equal(maximum + 1, response.CalculateSize());
        Assert.Equal(maximum + 1, response.ToByteArray().Length);
        Assert.True(NodeShapes.IsValid(plan));
        Assert.All(plan.Items, item => Assert.True(NodeShapes.IsValid(item)));
        Assert.False(NodeShapes.IsValid(response));
        Assert.False(FileServiceHandler.RemovalPlanResponseFits(response));
        outer.Value.Response = response.ToByteString();
        Assert.False(RoutedFileResponseValidation.PlanRemoval(outer, target, request));
    }

}
