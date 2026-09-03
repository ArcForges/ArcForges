// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using ArcForges.Contracts.Foundation;
using ArcForges.Contracts.LocalRpc;
using ArcForges.Contracts.LocalRpc.Notes;
using ArcForges.Contracts.LocalRpc.Scope;
using ArcForges.Contracts.LocalRpc.Slate;

namespace ArcForges.Tests.ContractCompatibilityTests;

internal static class LocalRpcFixtures
{
    private static readonly DateTimeOffset FixedTimestamp = new(2026, 9, 2, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid FixedCorrelationId = new("11111111-1111-1111-1111-111111111111");
    private static readonly Guid FixedCommandId = new("22222222-2222-2222-2222-222222222222");
    private static readonly Guid FixedInstanceId = new("33333333-3333-3333-3333-333333333333");
    private static readonly Guid FixedResourceId = new("44444444-4444-4444-4444-444444444444");
    private static readonly Guid FixedSessionId = new("66666666-6666-6666-6666-666666666666");

    internal static ActorContextDto ActorContext() =>
        new()
        {
            ActorChain =
            [
                new ActorChainEntryDto
                {
                    Principal = new SecurityPrincipalDto
                    {
                        Kind = "human",
                        PrincipalId = "user-12345",
                        DisplayNameKey = "Primary User",
                    },
                    Role = "initiator",
                },
            ],
            GrantedScopes = ["arcnotes.read", "arcnotes.write"],
            Correlation = new InvocationCorrelationDto
            {
                CorrelationId = FixedCorrelationId,
                TaskId = new TaskId(Guid.Parse("11111111-2222-3333-4444-555555555555")),
            },
        };

    internal static ResourceRef LocalResource() =>
        FoundationFixtures.LocalResource();

    internal static ArtifactRef SampleArtifact() =>
        FoundationFixtures.Artifact();

    internal static RegisterInstanceRequest RegisterRequest() =>
        new()
        {
            Product = ProductId.ArcNotes,
            Instance = new InstanceId(FixedInstanceId),
            ProcessId = 1234,
            Transport = "namedpipe",
            Endpoint = "arcforges-notes-1234",
            BuildId = "2026.09.02.1",
            ContractSet = "localrpc.v1",
            StartedAtUtc = FixedTimestamp,
            Capabilities =
            [
                new CapabilityDescriptor
                {
                    CapabilityId = "arcnotes.search.documents",
                    OwnerProduct = ProductId.ArcNotes,
                    Read = true,
                    Idempotent = true,
                },
            ],
        };

    internal static RegisterInstanceResult RegisterResult() =>
        new()
        {
            Accepted = true,
            SessionToken = "sess-token-abc123xyz",
            Lease = TimeSpan.FromSeconds(30),
        };

    internal static HeartbeatRequest HeartbeatReq() =>
        new()
        {
            Instance = new InstanceId(FixedInstanceId),
            SessionToken = "sess-token-abc123xyz",
            Health = ProviderHealth.Ready,
            ActiveTaskCount = 2,
            QueueDepth = 0,
            ActiveDocuments = [new DocumentId(FixedResourceId)],
        };

    internal static HeartbeatResult HeartbeatRes() =>
        new()
        {
            Accepted = true,
            Lease = TimeSpan.FromSeconds(30),
        };

    internal static RouteRequest RouteReq() =>
        new()
        {
            TargetInstance = new InstanceId(FixedInstanceId),
            Document = new DocumentId(FixedResourceId),
            CapabilityId = "arcnotes.blocks.read",
        };

    internal static RouteResult RouteRes() =>
        new()
        {
            Resolved = true,
            Instance = new InstanceId(FixedInstanceId),
            Endpoint = "arcforges-notes-1234",
        };

    internal static RequestApprovalRequest RequestApprovalReq() =>
        new()
        {
            Command = new CommandId(FixedCommandId),
            Task = new TaskId(Guid.Parse("11111111-2222-3333-4444-555555555555")),
            TargetResource = LocalResource(),
            ProposedEffect = "Overwrite heading block in active document",
            RiskClass = "R1",
            ExpiresAtUtc = FixedTimestamp.AddMinutes(5),
        };

    internal static RequestApprovalResult RequestApprovalRes() =>
        new()
        {
            ApprovalId = new Guid("99999999-9999-9999-9999-999999999999"),
            Accepted = true,
        };

    internal static ResolveApprovalRequest ResolveApprovalReq() =>
        new()
        {
            Command = new CommandId(FixedCommandId),
            ApprovalId = new Guid("99999999-9999-9999-9999-999999999999"),
            Decision = ApprovalDecision.Approved,
            ExpectedRevision = new Revision(1),
        };

    internal static ResolveApprovalResult ResolveApprovalRes() =>
        new()
        {
            Accepted = true,
            NewRevision = new Revision(2),
        };

    internal static ConnectionEstablishedNotice ConnectionNotice() =>
        new()
        {
            Instance = new InstanceId(FixedInstanceId),
            Product = ProductId.ArcNotes,
            Transport = "namedpipe",
            Endpoint = "arcforges-notes-1234",
            ConnectedAtUtc = FixedTimestamp,
        };

    internal static InsertBlocksRequest InsertBlocksReq() =>
        new()
        {
            CommandId = new CommandId(FixedCommandId),
            Actor = ActorContext(),
            TargetResource = LocalResource(),
            ExpectedRevision = 1,
            IssuedAtUtc = FixedTimestamp,
            DeadlineUtc = FixedTimestamp.AddSeconds(30),
            CorrelationId = FixedCorrelationId,
            DocumentRef = LocalResource(),
            Blocks =
            [
                new BlockCreateDto
                {
                    BlockType = "paragraph",
                    ContentJson = "{\"text\":\"Hello ArcForges LocalRpc\"}",
                },
            ],
            ReviewMode = NotesReviewMode.Auto,
        };

    internal static InsertBlocksResponse InsertBlocksRes() =>
        new()
        {
            CommandId = FixedCommandId,
            Status = MutationStatus.Succeeded,
            NewRevision = 2,
            ArtifactRefs = [],
            Warnings = [],
            Value = new DocumentMutationResultDto
            {
                DocumentRef = LocalResource(),
                ChangedBlockIds = [new Guid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")],
                ReviewRequired = false,
            },
        };

    internal static ArcResult<InsertBlocksResponse> ArcResultInsertBlocks() =>
        ArcResult<InsertBlocksResponse>.Success(InsertBlocksRes(), new Revision(2));

    internal static ArcForges.Contracts.LocalRpc.Scope.SearchResourcesRequest ScopeSearchReq() =>
        new()
        {
            RequestId = FixedCorrelationId,
            Actor = ActorContext(),
            Text = "temperature",
            Limit = 10,
        };

    internal static ArcForges.Contracts.LocalRpc.Scope.SearchResourcesResponse ScopeSearchRes() =>
        new()
        {
            Items =
            [
                new ScopeResourceHitDto
                {
                    ResourceRef = LocalResource(),
                    Kind = "capture",
                    Title = "Thermal Chamber 01",
                    MatchKind = "title",
                    Anchors = [],
                    Score = "0.95",
                },
            ],
            SnapshotRevision = 1,
        };

    internal static GetProjectSnapshotRequest SlateProjectReq() =>
        new()
        {
            RequestId = FixedCorrelationId,
            Actor = ActorContext(),
            ProjectRef = LocalResource(),
        };

    internal static GetProjectSnapshotResponse SlateProjectRes() =>
        new()
        {
            Value = new ProjectSnapshotDto
            {
                ProjectRef = LocalResource(),
                Title = "Feature Film Trailer",
                Revision = 1,
                RootSequenceId = FixedSessionId,
                AssetIds = [FixedResourceId],
                SequenceIds = [FixedSessionId],
            },
            SnapshotRevision = 1,
        };
}
