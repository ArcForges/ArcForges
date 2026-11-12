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

/// <summary>Published 450.1 response consumers; a synthetic envelope does not prove a native effect or a real center.</summary>
public sealed class FileMutationFleetResponseValidationTests
{
    [Fact]
    public void WriteSuccessBindsActualRequestTargetCommandHashAndSignedAudit()
    {
        var target = CommandIds.New();
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new FilePath { WorkspaceId = CommandIds.New(), Path = "target" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFromUtf8("payload"),
        };
        var result = new FileMutationResult
        {
            CommandId = request.Meta.CommandId.Clone(),
            SizeBytes = (ulong)request.Data.Length,
            Sha256 = ByteString.CopyFrom(SHA256.HashData(request.Data.Span)),
        };
        var observation = new FileAuditObservation
        {
            Kind = FileAuditKind.WrittenBytes,
            SizeBytes = result.SizeBytes,
            DigestInputBytes = result.SizeBytes,
            Sha256 = result.Sha256,
        };
        var inner = new FileServiceWriteFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Value = new FileServiceWriteFileValue { Result = result },
            Audit = new FileAuditMetadata { Observations = { observation } },
        };
        var outer = new FleetServiceWriteNodeFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Value = new FleetServiceWriteNodeFileValue { NodeId = target.Clone() },
        };
        bool Accept() { outer.Value.Response = inner.ToByteString(); return RoutedFileResponseValidation.Write(outer, target, request); }

        Assert.True(NodeShapes.IsValid(inner));
        Assert.True(Accept());
        result.CommandId = CommandIds.New();
        Assert.False(Accept());
        result.CommandId = request.Meta.CommandId.Clone();
        result.SizeBytes++;
        Assert.False(Accept());
        result.SizeBytes--;
        observation.Sha256 = ByteString.CopyFrom(new byte[32]);
        Assert.False(Accept());
        observation.Sha256 = result.Sha256;
        inner.Audit.Observations.Clear();
        Assert.False(Accept());
        inner.Audit.Observations.Add(observation);
        result.Replacements = 1;
        Assert.False(Accept());
        result.ClearReplacements();
        outer.Value.NodeId = CommandIds.New();
        Assert.False(Accept());
        outer.Value.NodeId = target.Clone();
        inner.Meta.CorrelationId = CommandIds.New();
        Assert.False(Accept());
    }

    [Fact]
    public void EditBindsOccurrenceAndKeepsActualOutcomeUnknownDistinct()
    {
        var target = CommandIds.New();
        var request = new FileServiceEditFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new FilePath { WorkspaceId = CommandIds.New(), Path = "target" },
            OldText = "old",
            NewText = "new",
            ExpectedOccurrences = 2,
            ExpectedSha256 = ByteString.CopyFrom(new byte[32]),
        };
        var result = new FileMutationResult
        {
            CommandId = request.Meta.CommandId.Clone(),
            SizeBytes = 5,
            Sha256 = ByteString.CopyFrom(new byte[32]),
            Replacements = 2,
        };
        var inner = new FileServiceEditFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Value = new FileServiceEditFileValue { Result = result },
            Audit = new FileAuditMetadata
            {
                Observations =
            {
                new FileAuditObservation { Kind = FileAuditKind.WrittenBytes, SizeBytes = 5, DigestInputBytes = 5, Sha256 = result.Sha256 },
            }
            },
        };
        var outer = new FleetServiceEditNodeFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Value = new FleetServiceEditNodeFileValue { NodeId = target.Clone() },
        };
        bool Accept() { outer.Value.Response = inner.ToByteString(); return RoutedFileResponseValidation.Edit(outer, target, request); }

        Assert.True(NodeShapes.IsValid(inner));
        Assert.True(Accept());
        result.Replacements = 1;
        Assert.False(Accept());
        result.Replacements = 2;
        inner.Error = new ArcError
        {
            Category = ErrorCategory.Execution,
            Code = "operation_failed",
            MessageKey = "error.execution.operation_failed",
            Effect = EffectCertainty.Unknown,
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            CorrelationId = request.Meta.CorrelationId.Clone(),
            Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "file_outcome_unknown" } },
        };
        inner.Audit = null;
        Assert.True(Accept());
        inner.Error.Details.State.Reason = "other";
        Assert.False(Accept());
        inner.Error.Details.State.Reason = "file_outcome_unknown";
        inner.Error.Retry.Mode = RetryMode.AfterTime;
        Assert.False(Accept());
    }

    [Fact]
    public void PublishedOpenLimitNamesUseRealRequestFactsAndCanonicalDecimal()
    {
        var target = CommandIds.New();
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new FilePath { WorkspaceId = CommandIds.New(), Path = "target" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFromUtf8("short"),
        };
        var error = new ArcError
        {
            Category = ErrorCategory.Resource,
            Code = "too_large",
            MessageKey = "error.resource.too_large",
            Effect = EffectCertainty.DidNotHappen,
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            CorrelationId = request.Meta.CorrelationId.Clone(),
            Details = new ErrorDetails { Limit = new LimitFailure { LimitName = "file_existing_bytes", Maximum = new WireDecimal { Value = "4194304" } } },
        };
        var inner = new FileServiceWriteFileResponse { Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() }, Error = error };
        var outer = new FleetServiceWriteNodeFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Value = new FleetServiceWriteNodeFileValue { NodeId = target.Clone() },
        };
        bool Accept() { outer.Value.Response = inner.ToByteString(); return RoutedFileResponseValidation.Write(outer, target, request); }

        Assert.True(Accept()); // Existing-file size is unknown even for an expected-absent request.
        error.Details.Limit.Available = new WireDecimal { Value = "1.00" };
        Assert.True(NodeShapes.IsValid(error));
        Assert.True(Accept());
        error.Details.Limit.Available.Value = "01.0";
        Assert.False(Accept());
        error.Details.Limit.Available.Value = "1.00";
        error.Details.Limit.LimitName = "removal_plan_response_bytes";
        Assert.False(Accept()); // Canonical names cannot be reinterpreted as another method's matching 4 MiB limit.
        error.Details.Limit.LimitName = "removal_ownership_input_bytes";
        Assert.False(Accept()); // A Plan-only canonical name cannot become an opaque write limit.
        error.Details.Limit.LimitName = "opaque.file.bound";
        Assert.True(Accept());
        error.Details.Limit.Maximum.Value = "4194304.00";
        Assert.True(NodeShapes.IsValid(error)); // Published .NET 450.1 accepts the noncanonical wire value.
        Assert.False(Accept());
        error.Details.Limit.Maximum.Value = "4194304";
        error.Details.Limit.LimitName = "file_edit_result_bytes";
        Assert.False(Accept());
        error.Details.Limit.LimitName = "path_bytes";
        error.Details.Limit.Maximum.Value = "4096";
        Assert.False(Accept());
        request.Path.Path = new string('x', 4097);
        Assert.True(Accept());
        error.Details.Limit.LimitName = "opaque";
        Assert.True(Accept());
        error.Details.Limit.LimitName = "workspace_root_path_bytes";
        Assert.False(Accept());
        error.Details.Limit.LimitName = "file_write_bytes";
        error.Details.Limit.Maximum.Value = "196608";
        Assert.False(Accept());
        request.Data = ByteString.CopyFrom(new byte[196_609]);
        Assert.True(Accept());
    }

    [Fact]
    public void ConflictReasonMustMatchTheOriginalWritePreconditionAndCorrelation()
    {
        var target = CommandIds.New();
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new FilePath { WorkspaceId = CommandIds.New(), Path = "target" },
            ExpectedAbsent = true,
            Data = ByteString.Empty,
        };
        var error = new ArcError
        {
            Category = ErrorCategory.Conflict,
            Code = "file_changed",
            MessageKey = "error.conflict.file_changed",
            Effect = EffectCertainty.DidNotHappen,
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            CorrelationId = request.Meta.CorrelationId.Clone(),
            Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "expected_absent_conflict" } },
        };
        var inner = new FileServiceWriteFileResponse { Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() }, Error = error };
        var outer = new FleetServiceWriteNodeFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Value = new FleetServiceWriteNodeFileValue { NodeId = target.Clone() },
        };
        bool Accept() { outer.Value.Response = inner.ToByteString(); return RoutedFileResponseValidation.Write(outer, target, request); }

        Assert.True(Accept());
        error.Details.State.Reason = "hash_mismatch";
        Assert.False(Accept());
        request.ExpectedSha256 = ByteString.CopyFrom(new byte[32]);
        Assert.True(Accept());
        error.Details.State.Reason = "expected_absent_conflict";
        Assert.False(Accept());
        error.CorrelationId = CommandIds.New();
        Assert.False(Accept());
    }
}
