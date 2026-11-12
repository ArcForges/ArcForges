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

/// <summary>Published 450.1 consumer checks on synthetic status envelopes, not proof of a persisted file effect or a real center.</summary>
public sealed class FileOperationFleetResponseValidationTests
{
    [Fact]
    public void CompletedStatusUsesOriginalKindAndKnownTargetWithoutInventingOriginalRequestFacts()
    {
        var target = CommandIds.New();
        var statusCorrelation = CommandIds.New();
        var command = CommandIds.New();
        var request = new FileServiceGetFileOperationRequest
        {
            Meta = new RequestMeta { CorrelationId = statusCorrelation },
            OperationCommandId = command.Clone(),
        };
        var error = new ArcError
        {
            Category = ErrorCategory.Resource,
            Code = "too_large",
            MessageKey = "error.resource.too_large",
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            Effect = EffectCertainty.DidNotHappen,
            CorrelationId = CommandIds.New(), // the original operation's correlation is not the status call's
            Details = new ErrorDetails { Limit = new LimitFailure { LimitName = "existing_file_size_bytes", Maximum = new WireDecimal { Value = "4194304" } } },
        };
        var operation = new FileOperation
        {
            CommandId = command.Clone(),
            Kind = FileOperationKind.Write,
            State = FileOperationState.Completed,
            RequestSha256 = ByteString.CopyFrom(new byte[32]),
            CreatedAt = ProtoTime.ToInstant(DateTimeOffset.UtcNow),
            UpdatedAt = ProtoTime.ToInstant(DateTimeOffset.UtcNow),
            Held = false,
            Acknowledged = false,
            WorkspacePath = new FilePath { WorkspaceId = CommandIds.New(), Path = "target" },
            Error = error,
        };
        var inner = new FileServiceGetFileOperationResponse
        {
            Meta = new ResponseMeta { CorrelationId = statusCorrelation.Clone() },
            Value = new FileServiceGetFileOperationValue { Operation = operation },
        };
        var response = new FleetServiceGetNodeFileOperationResponse
        {
            Meta = new ResponseMeta { CorrelationId = statusCorrelation.Clone() },
            Value = new FleetServiceGetNodeFileOperationValue { NodeId = target.Clone() },
        };
        bool Accept()
        {
            response.Value.Response = inner.ToByteString();
            return RoutedFileResponseValidation.GetFileOperation(response, target, request);
        }

        Assert.True(NodeShapes.IsValid(inner));
        Assert.True(Accept());
        error.Details.Limit.LimitName = "removal_plan_response_bytes";
        Assert.False(Accept()); // A removal plan is not a persisted file operation kind.
        error.Details.Limit.LimitName = "file_existing_bytes";
        Assert.True(Accept());
        error.Details.Limit.LimitName = "file_write_bytes";
        Assert.False(Accept());
        error.Details.Limit.LimitName = "removal_total_bytes";
        Assert.False(Accept());
        error.Details.Limit.LimitName = "existing_file_size_bytes";
        error.Details.Limit.Maximum.Value = "4194304.00";
        Assert.True(NodeShapes.IsValid(error)); // The published validator accepts it; the consumer must reject noncanonical decimal.
        Assert.False(Accept());
        error.Details.Limit.Maximum.Value = "4194304";
        error.Details.Limit.LimitName = "bad name";
        Assert.False(Accept());
        error.Details.Limit.LimitName = "opaque";
        operation.Kind = FileOperationKind.Edit;
        Assert.True(Accept()); // Original input and occurrence facts are unknown; both 4 MiB candidates remain possible.
        error.Details.Limit.LimitName = "file_edit_result_bytes";
        Assert.True(Accept());
        error.Details.Limit.LimitName = "path_bytes";
        error.Details.Limit.Maximum.Value = "4096";
        Assert.False(Accept()); // The caller-bound persisted path is a known, bounded target.
        error.Details.Limit.LimitName = "file_existing_bytes";
        error.Details.Limit.Maximum.Value = "4194304";
        response.Value.NodeId = CommandIds.New();
        Assert.False(Accept());
        response.Value.NodeId = target.Clone();
        operation.CommandId = CommandIds.New();
        Assert.False(Accept());
        operation.CommandId = command.Clone();
        operation.Held = true;
        Assert.False(Accept());
    }

    [Fact]
    public void UnknownStatusPreservesOriginalErrorAndNeverTurnsItIntoAMethodError()
    {
        var target = CommandIds.New();
        var command = CommandIds.New();
        var correlation = CommandIds.New();
        var originalCorrelation = CommandIds.New();
        var request = new FileServiceGetFileOperationRequest { Meta = new RequestMeta { CorrelationId = correlation }, OperationCommandId = command };
        var operation = new FileOperation
        {
            CommandId = command.Clone(),
            Kind = FileOperationKind.Write,
            State = FileOperationState.Unknown,
            RequestSha256 = ByteString.CopyFrom(new byte[32]),
            CreatedAt = ProtoTime.ToInstant(DateTimeOffset.UtcNow),
            UpdatedAt = ProtoTime.ToInstant(DateTimeOffset.UtcNow),
            Held = true,
            Acknowledged = false,
            WorkspacePath = new FilePath { WorkspaceId = CommandIds.New(), Path = "target" },
            Error = new ArcError
            {
                Category = ErrorCategory.Execution,
                Code = "operation_failed",
                MessageKey = "error.execution.operation_failed",
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                Effect = EffectCertainty.Unknown,
                CorrelationId = originalCorrelation,
                Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "file_outcome_unknown" } },
            },
        };
        var inner = new FileServiceGetFileOperationResponse
        {
            Meta = new ResponseMeta { CorrelationId = correlation.Clone() },
            Value = new FileServiceGetFileOperationValue { Operation = operation },
        };
        var response = new FleetServiceGetNodeFileOperationResponse
        {
            Meta = new ResponseMeta { CorrelationId = correlation.Clone() },
            Value = new FleetServiceGetNodeFileOperationValue { NodeId = target.Clone() },
        };
        bool Accept()
        {
            response.Value.Response = inner.ToByteString();
            return RoutedFileResponseValidation.GetFileOperation(response, target, request);
        }

        Assert.True(Accept());
        operation.Held = false;
        Assert.False(Accept());
        operation.Acknowledged = true;
        Assert.True(Accept());
        operation.Error.Effect = EffectCertainty.DidNotHappen;
        Assert.False(Accept());
        operation.Error.Effect = EffectCertainty.Unknown;
        operation.Error.Details.State.Reason = "other";
        Assert.False(Accept());
        operation.Error.Details.State.Reason = "file_outcome_unknown";
        operation.State = FileOperationState.Prepared;
        Assert.False(Accept());
    }
}
