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

/// <summary>Actual 450.1 workspace shapes plus caller-bound relay consumer checks; these do not stand in for a real center.</summary>
public sealed class WorkspaceFleetResponseValidationTests
{
    [Fact]
    public void RegistrationLimitNamesAreOpenButCanonicalNamesAndRequestFactsRemainBound()
    {
        var target = CommandIds.New();
        var meta = Tasks.Meta();
        var request = new WorkspaceServiceRegisterWorkspaceRequest { Meta = meta, Path = "/" + new string('x', 4096) };
        var error = TooLarge(meta.CorrelationId, "other_valid_bound", "4096");
        var inner = new WorkspaceServiceRegisterWorkspaceResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Error = error,
        };
        var result = new FleetServiceRegisterNodeWorkspaceResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServiceRegisterNodeWorkspaceValue { NodeId = target.Clone(), Response = inner.ToByteString() },
        };
        Assert.True(NodeShapes.IsValid(error));
        Assert.True(RoutedFileResponseValidation.RegisterWorkspace(result, target, request));

        error.Details.Limit.LimitName = "workspace_root_path_bytes";
        result.Value.Response = inner.ToByteString();
        Assert.True(RoutedFileResponseValidation.RegisterWorkspace(result, target, request));
        error.Details.Limit.LimitName = "path_bytes";
        result.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.RegisterWorkspace(result, target, request));
        error.Details.Limit.LimitName = "opaque";
        error.Details.Limit.Maximum.Value = "4096.00";
        Assert.True(NodeShapes.IsValid(error));
        result.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.RegisterWorkspace(result, target, request));
        error.Details.Limit.Maximum.Value = "4096";
        request.Path = "/short";
        result.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.RegisterWorkspace(result, target, request));

        request.Path = "/" + new string('x', 4096);
        var outer = new FleetServiceRegisterNodeWorkspaceResponse { Meta = result.Meta.Clone(), Error = error.Clone() };
        Assert.True(RoutedFileResponseValidation.RegisterWorkspace(outer, target, request));
        outer.Error.Details.Limit.LimitName = "file_write_bytes";
        Assert.False(RoutedFileResponseValidation.RegisterWorkspace(outer, target, request));
    }

    [Fact]
    public void ListAndGetCheckWorkspaceIdentityFiltersAndExactMetadataTranscript()
    {
        var target = CommandIds.New();
        var meta = new RequestMeta { CorrelationId = CommandIds.New() };
        var workspace = Workspace();
        var listRequest = new WorkspaceServiceListWorkspacesRequest
        {
            Meta = meta.Clone(),
            Kinds = { WorkspaceKind.Registered },
            Page = new PageRequest { Limit = 1 },
        };
        var listInner = new WorkspaceServiceListWorkspacesResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new WorkspaceServiceListWorkspacesValue { Workspaces = { workspace.Clone() }, Page = new PageState { HasMore = false } },
            Audit = WorkspaceAuditMetadata.ForRecords([workspace]),
        };
        var list = new FleetServiceListNodeWorkspacesResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServiceListNodeWorkspacesValue { NodeId = target.Clone(), Response = listInner.ToByteString() },
        };
        Assert.True(NodeShapes.IsValid(listInner));
        Assert.True(RoutedFileResponseValidation.ListWorkspaces(list, target, listRequest));
        list.Value.NodeId = CommandIds.New();
        Assert.False(RoutedFileResponseValidation.ListWorkspaces(list, target, listRequest));
        list.Value.NodeId = target.Clone();
        listInner.Audit.Observations[0].Sha256 = ByteString.CopyFrom(new byte[32]);
        list.Value.Response = listInner.ToByteString();
        Assert.False(RoutedFileResponseValidation.ListWorkspaces(list, target, listRequest));
        listInner.Audit = WorkspaceAuditMetadata.ForRecords([workspace]);
        listInner.Value.Workspaces[0].Kind = WorkspaceKind.Remote;
        list.Value.Response = listInner.ToByteString();
        Assert.False(RoutedFileResponseValidation.ListWorkspaces(list, target, listRequest));

        var getRequest = new WorkspaceServiceGetWorkspaceRequest { Meta = meta.Clone(), WorkspaceId = workspace.WorkspaceId.Clone() };
        var getInner = new WorkspaceServiceGetWorkspaceResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new WorkspaceServiceGetWorkspaceValue { Workspace = workspace.Clone() },
            Audit = WorkspaceAuditMetadata.ForRecords([workspace]),
        };
        var get = new FleetServiceGetNodeWorkspaceResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServiceGetNodeWorkspaceValue { NodeId = target.Clone(), Response = getInner.ToByteString() },
        };
        Assert.True(NodeShapes.IsValid(getInner));
        Assert.True(RoutedFileResponseValidation.GetWorkspace(get, target, getRequest));
        getRequest.WorkspaceId = CommandIds.New();
        Assert.False(RoutedFileResponseValidation.GetWorkspace(get, target, getRequest));
        getRequest.WorkspaceId = workspace.WorkspaceId.Clone();
        getInner.Value.Workspace.Git.Dirty = false;
        getInner.Audit = WorkspaceAuditMetadata.ForRecords([getInner.Value.Workspace]);
        get.Value.Response = getInner.ToByteString();
        Assert.False(RoutedFileResponseValidation.GetWorkspace(get, target, getRequest));
    }

    [Fact]
    public void UnregistrationReceiptAndResponseMetadataBindTheExactRequest()
    {
        var target = CommandIds.New();
        var meta = Tasks.Meta();
        var request = new WorkspaceServiceUnregisterWorkspaceRequest { Meta = meta, WorkspaceId = CommandIds.New() };
        var inner = new WorkspaceServiceUnregisterWorkspaceResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new WorkspaceServiceUnregisterWorkspaceValue
            {
                Receipt = new Receipt { CommandId = meta.CommandId.Clone(), Effect = EffectCertainty.Happened },
            },
        };
        var result = new FleetServiceUnregisterNodeWorkspaceResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServiceUnregisterNodeWorkspaceValue { NodeId = target.Clone(), Response = inner.ToByteString() },
        };
        Assert.True(NodeShapes.IsValid(inner));
        Assert.True(RoutedFileResponseValidation.UnregisterWorkspace(result, target, request));
        inner.Value.Receipt.CommandId = CommandIds.New();
        result.Value.Response = inner.ToByteString();
        Assert.False(RoutedFileResponseValidation.UnregisterWorkspace(result, target, request));
        inner.Value.Receipt.CommandId = meta.CommandId.Clone();
        result.Value.Response = inner.ToByteString();
        // A repeated command may have a new per-attempt correlation. The durable response is replayed byte for byte.
        request.Meta = meta.Clone();
        request.Meta.CorrelationId = CommandIds.New();
        Assert.True(RoutedFileResponseValidation.UnregisterWorkspace(result, target, request));
        inner.Meta = null;
        result.Value.Response = inner.ToByteString();
        Assert.True(NodeShapes.IsValid(inner));
        Assert.True(RoutedFileResponseValidation.UnregisterWorkspace(result, target, request));
        inner.Meta = new ResponseMeta();
        result.Value.Response = inner.ToByteString();
        Assert.False(NodeShapes.IsValid(inner));
        Assert.False(RoutedFileResponseValidation.UnregisterWorkspace(result, target, request));
    }

    private static Workspace Workspace() => new()
    {
        WorkspaceId = CommandIds.New(),
        Kind = WorkspaceKind.Registered,
        State = WorkspaceState.Active,
        Name = "workspace",
        RootPath = "/test/workspace",
        Git = new GitStatusSummary { Quality = GitStatusQuality.Unknown },
    };

    private static ArcError TooLarge(Id correlation, string name, string maximum) => new()
    {
        Category = ErrorCategory.Resource,
        Code = "too_large",
        MessageKey = "error.resource.too_large",
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Effect = EffectCertainty.DidNotHappen,
        CorrelationId = correlation.Clone(),
        Details = new ErrorDetails { Limit = new LimitFailure { LimitName = name, Maximum = new WireDecimal { Value = maximum } } },
    };
}
