// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual published shapes and method-profile consumer checks; transport signatures are tested separately.</summary>
public sealed class AttemptQualificationConsumerTests
{
    [Theory]
    [InlineData("attempt_references_unverified")]
    [InlineData("attempt_tracking_unverified")]
    public void OnlyTheExactAttemptPlanProfileAcceptsTheTwoReasons(string reason)
    {
        var target = CommandIds.New();
        var meta = Tasks.Meta();
        var request = new FileServicePlanRemovalRequest { Meta = meta.Clone(), AttemptId = CommandIds.New() };
        var error = Error(meta.CorrelationId, reason);
        var inner = new FileServicePlanRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Error = error,
        };
        var outer = new FleetServicePlanNodeRemovalResponse
        {
            Meta = inner.Meta.Clone(),
            Value = new FleetServicePlanNodeRemovalValue { NodeId = target.Clone(), Response = inner.ToByteString() },
        };
        Assert.True(NodeShapes.IsValid(error));
        Assert.Equal(error.ToByteArray(), ArcError.Parser.ParseFrom(error.ToByteArray()).ToByteArray());
        Assert.True(RoutedFileResponseValidation.PlanRemoval(outer, target, request));
        Assert.False(RoutedFileResponseValidation.PlanRemoval(outer, CommandIds.New(), request));
        var workspace = new FileServicePlanRemovalRequest
        {
            Meta = meta.Clone(),
            WorkspacePath = new FilePath { WorkspaceId = CommandIds.New(), Path = "tree" },
        };
        Assert.False(RoutedFileResponseValidation.PlanRemoval(outer, target, workspace));
        Assert.False(RoutedFileResponseValidation.PlanRemoval(
            new FleetServicePlanNodeRemovalResponse { Meta = inner.Meta.Clone(), Error = error.Clone() }, target, request));

        void Reject(Action<ArcError> change)
        {
            inner.Error = error.Clone();
            change(inner.Error);
            outer.Value.Response = inner.ToByteString();
            Assert.False(RoutedFileResponseValidation.PlanRemoval(outer, target, request));
        }
        Reject(value => value.Details.State.State = "attempt");
        Reject(value => value.Details.State.Resource = new AggregateRef { Kind = "attempt", Id = request.AttemptId.Clone() });
        Reject(value => value.Effect = EffectCertainty.Happened);
        Reject(value => value.Effect = EffectCertainty.Unknown);
        Reject(value => value.Retry.RetryAt = ProtoTime.ToInstant(DateTimeOffset.UtcNow.AddSeconds(1)));
        Reject(value => value.Retry.ReconciliationOperation = "arcforges.node.v1.FileService/GetFileOperation");
        Reject(value => value.Retry.Mode = RetryMode.SameCommand);
        Reject(value => value.CorrelationId = CommandIds.New());
        Reject(value => value.Code = "file_access_denied");
        Reject(value => value.Details.State.Reason = "other_generic_reason");
        var genericControl = Error(meta.CorrelationId, "other_generic_reason");
        Assert.True(NodeShapes.IsValid(genericControl)); // Representation is not a method whitelist.

        var write = new FileServiceWriteFileRequest
        {
            Meta = meta.Clone(),
            Path = workspace.WorkspacePath.Clone(),
            ExpectedAbsent = true,
            Data = ByteString.CopyFromUtf8("fixture"),
        };
        var writeInner = new FileServiceWriteFileResponse { Meta = inner.Meta.Clone(), Error = error.Clone() };
        var writeOuter = new FleetServiceWriteNodeFileResponse
        {
            Meta = inner.Meta.Clone(),
            Value = new FleetServiceWriteNodeFileValue { NodeId = target.Clone(), Response = writeInner.ToByteString() },
        };
        Assert.True(NodeShapes.IsValid(writeInner));
        Assert.False(RoutedFileResponseValidation.Write(writeOuter, target, write));
        writeOuter.Value = null;
        writeOuter.Error = error.Clone();
        Assert.False(RoutedFileResponseValidation.Write(writeOuter, target, write));

        // The attempt-specific ban does not remove a legitimate existing Fleet outer invalid_state.
        var replayWindow = Error(meta.CorrelationId, "replay_window_passed");
        replayWindow.Effect = EffectCertainty.Unknown;
        var ordinaryOuter = new FleetServicePlanNodeRemovalResponse { Meta = inner.Meta.Clone(), Error = replayWindow };
        Assert.True(RoutedFileResponseValidation.PlanRemoval(ordinaryOuter, target, request));
    }

    private static ArcError Error(Id correlation, string reason) => new()
    {
        Category = ErrorCategory.State,
        Code = "invalid_state",
        MessageKey = "error.state.invalid_state",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = correlation.Clone(),
        Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = reason } },
    };
}
