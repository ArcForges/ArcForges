// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Capabilities.Tests;

public sealed class CapabilityRegistryTests
{
    [Xunit.Fact]
    public void InitialMatrixMatchesIndependentHardCodedProductAndCloudCatalogueOracle()
    {
        var registry = CapabilityRegistry.CreateInitial();
        var entries = registry.Registrations;

        ExpectedCapability[] expected =
        {
            new("IScopeOperations.ListSessions", "Product", "arcscope", "ScopeOperationsService", "ListSessions", "arcforges.local.scope.v1.ScopeOperationsServiceListSessionsRequest", "arcforges.local.scope.v1.ScopeOperationsServiceListSessionsResponse", "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, false, 4),
            new("IScopeOperations.GetSession", "Product", "arcscope", "ScopeOperationsService", "GetSession", "arcforges.local.scope.v1.ScopeOperationsServiceGetSessionRequest", "arcforges.local.scope.v1.ScopeOperationsServiceGetSessionResponse", "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, false, 4),
            new("IScopeOperations.ListCaptures", "Product", "arcscope", "ScopeOperationsService", "ListCaptures", "arcforges.local.scope.v1.ScopeOperationsServiceListCapturesRequest", "arcforges.local.scope.v1.ScopeOperationsServiceListCapturesResponse", "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, false, 4),
            new("IScopeOperations.GetConfigurationSnapshot", "Product", "arcscope", "ScopeOperationsService", "GetConfigurationSnapshot", "arcforges.local.scope.v1.ScopeOperationsServiceGetConfigurationSnapshotRequest", "arcforges.local.scope.v1.ScopeOperationsServiceGetConfigurationSnapshotResponse", "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, false, 4),
            new("IScopeOperations.RunMeasurement", "Product", "arcscope", "ScopeOperationsService", "RunMeasurement", "arcforges.local.scope.v1.ScopeOperationsServiceRunMeasurementRequest", "arcforges.local.scope.v1.ScopeOperationsServiceRunMeasurementResponse", "R2", "perOperation", "none", "NI", RetryMode.Never, EffectKind.LocalWrite, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, true, 1),
            new("IScopeOperations.RunAnalysis", "Product", "arcscope", "ScopeOperationsService", "RunAnalysis", "arcforges.local.scope.v1.ScopeOperationsServiceRunAnalysisRequest", "arcforges.local.scope.v1.ScopeOperationsServiceRunAnalysisResponse", "R2", "perOperation", "none", "NI", RetryMode.Reconcile, EffectKind.LocalWrite, "IProductLifecycle.GetJob", BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, true, 1),
            new("IScopeOperations.CompareSessions", "Product", "arcscope", "ScopeOperationsService", "CompareSessions", "arcforges.local.scope.v1.ScopeOperationsServiceCompareSessionsRequest", "arcforges.local.scope.v1.ScopeOperationsServiceCompareSessionsResponse", "R2", "none", "none", "NI", RetryMode.Never, EffectKind.LocalWrite, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, true, 1),
            new("IScopeOperations.CreateAnnotation", "Product", "arcscope", "ScopeOperationsService", "CreateAnnotation", "arcforges.local.scope.v1.ScopeOperationsServiceCreateAnnotationRequest", "arcforges.local.scope.v1.ScopeOperationsServiceCreateAnnotationResponse", "R2", "perOperation", "none", "CC", RetryMode.SameCommand, EffectKind.LocalWrite, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, true, 1),
            new("IScopeOperations.CreateFinding", "Product", "arcscope", "ScopeOperationsService", "CreateFinding", "arcforges.local.scope.v1.ScopeOperationsServiceCreateFindingRequest", "arcforges.local.scope.v1.ScopeOperationsServiceCreateFindingResponse", "R2", "perOperation", "none", "CC", RetryMode.SameCommand, EffectKind.LocalWrite, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, true, 1),
            new("IScopeOperations.GenerateReport", "Product", "arcscope", "ScopeOperationsService", "GenerateReport", "arcforges.local.scope.v1.ScopeOperationsServiceGenerateReportRequest", "arcforges.local.scope.v1.ScopeOperationsServiceGenerateReportResponse", "R2", "perOperation", "none", "NI", RetryMode.Never, EffectKind.LocalWrite, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, true, 1),
            new("IScopeOperations.StartCapture", "Product", "arcscope", "ScopeOperationsService", "StartCapture", "arcforges.local.scope.v1.ScopeOperationsServiceStartCaptureRequest", "arcforges.local.scope.v1.ScopeOperationsServiceStartCaptureResponse", "R3", "perOperation", "none", "NI", RetryMode.Reconcile, EffectKind.ExternalWrite, "IScopeOperations.ListCaptures", BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, true, 1),
            new("IScopeOperations.StopCapture", "Product", "arcscope", "ScopeOperationsService", "StopCapture", "arcforges.local.scope.v1.ScopeOperationsServiceStopCaptureRequest", "arcforges.local.scope.v1.ScopeOperationsServiceStopCaptureResponse", "R3", "perOperation", "none", "IW", RetryMode.Reconcile, EffectKind.ExternalWrite, "IScopeOperations.ListCaptures", BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, true, 1),
            new("IScopeOperations.GetStructuredContext", "Product", "arcscope", "ScopeOperationsService", "GetStructuredContext", "arcforges.local.scope.v1.ScopeOperationsServiceGetStructuredContextRequest", "arcforges.local.scope.v1.ScopeOperationsServiceGetStructuredContextResponse", "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, false, 4),
            new("IChatOperations.ListConversations", "Product", "companion", "ChatOperationsService", "ListConversations", "arcforges.local.chat.v1.ChatOperationsServiceListConversationsRequest", "arcforges.local.chat.v1.ChatOperationsServiceListConversationsResponse", "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, false, 4),
            new("IChatOperations.GetConversation", "Product", "companion", "ChatOperationsService", "GetConversation", "arcforges.local.chat.v1.ChatOperationsServiceGetConversationRequest", "arcforges.local.chat.v1.ChatOperationsServiceGetConversationResponse", "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, false, 4),
            new("IChatOperations.CreateConversation", "Product", "companion", "ChatOperationsService", "CreateConversation", "arcforges.local.chat.v1.ChatOperationsServiceCreateConversationRequest", "arcforges.local.chat.v1.ChatOperationsServiceCreateConversationResponse", "R2", "none", "none", "CC", RetryMode.SameCommand, EffectKind.LocalWrite, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, true, 1),
            new("IChatOperations.AppendUserMessage", "Product", "companion", "ChatOperationsService", "AppendUserMessage", "arcforges.local.chat.v1.ChatOperationsServiceAppendUserMessageRequest", "arcforges.local.chat.v1.ChatOperationsServiceAppendUserMessageResponse", "R2", "none", "none", "AP", RetryMode.SameCommand, EffectKind.LocalWrite, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, true, 1),
            new("IChatOperations.StartAgentTurn", "Product", "companion", "ChatOperationsService", "StartAgentTurn", "arcforges.local.chat.v1.ChatOperationsServiceStartAgentTurnRequest", "arcforges.local.chat.v1.ChatOperationsServiceStartAgentTurnResponse", "R2", "perPlanStep", "none", "NI", RetryMode.Reconcile, EffectKind.CloudWrite, "IProductLifecycle.GetJob", BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, true, 1),
            new("IChatOperations.OpenArtifact", "Product", "companion", "ChatOperationsService", "OpenArtifact", "arcforges.local.chat.v1.ChatOperationsServiceOpenArtifactRequest", "arcforges.local.chat.v1.ChatOperationsServiceOpenArtifactResponse", "R1", "none", "ownedContent", "NI", RetryMode.Never, EffectKind.LocalWrite, null, BindingProtocol.InProcess, ToolLocality.Device, ExecutionLocus.Device, true, 1),
            new("search.query", "CloudService", "SearchService", "SearchService", "Query", "arcforges.publicapi.v1.SearchServiceQueryRequest", "arcforges.publicapi.v1.SearchServiceQueryResponse", "R1", "none", "none", "Q", RetryMode.SameCommand, EffectKind.PureRead, null, BindingProtocol.PublicGrpc, ToolLocality.Cloud, ExecutionLocus.Cloud, false, 4),
        };

        Xunit.Assert.Equal(expected.Length, entries.Count);
        Xunit.Assert.DoesNotContain(entries, entry => entry.Key == "IChatOperations.SubmitApproval");
        Xunit.Assert.Equal(expected.Select(item => item.Key).OrderBy(key => key, StringComparer.Ordinal),
            entries.Select(entry => entry.Key).OrderBy(key => key, StringComparer.Ordinal));
        foreach (var item in expected)
        {
            AssertMatches(item, registry.Find(item.Key)!);
        }

        var search = registry.Find("search.query")!;
        Xunit.Assert.Null(search.Owner.ProductApp);
        Xunit.Assert.Same(SearchService.Instance, search.Owner.CloudServiceIdentity);
        Xunit.Assert.Equal("none", search.Descriptor.Egress);
    }

    [Xunit.Fact]
    public void ConditionalWebSearchEgressIsNotFoldedIntoTheStaticSearchDescriptor()
    {
        var registry = CapabilityRegistry.CreateInitial();
        var search = registry.Find("search.query")!;
        Xunit.Assert.Equal("none", search.Descriptor.Egress);
        Xunit.Assert.Equal(ToolLocality.Cloud, search.Descriptor.Locality);
        Xunit.Assert.Equal(ExecutionLocus.Cloud, search.Descriptor.Execution);

        var externalWebVariant = search.Descriptor;
        externalWebVariant.Egress = "webSearch";
        var rejected = Xunit.Assert.Throws<CapabilityRegistryException>(() =>
            CapabilityRegistry.ValidateInitial(Replace(registry.Registrations, search.Key,
                new CapabilityRegistration(search.Owner, externalWebVariant))));
        Xunit.Assert.Equal(CapabilityRegistryFailure.MetadataMismatch, rejected.Failure);
    }

    [Xunit.Fact]
    public void CloudCatalogueEntryCannotBecomeOrSelectALocalTarget()
    {
        var registry = CapabilityRegistry.CreateInitial();
        var result = CapabilitySelector.Select(registry, "search.query", new EnumerationMustNotOccur<CapabilityTarget>());

        Xunit.Assert.Equal(CapabilitySelectionReason.CloudServiceNotLocalTarget, result.Reason);
        Xunit.Assert.Null(result.Target);
        Xunit.Assert.Empty(result.ConsideredTargets);
        Xunit.Assert.Null(registry.Find("search.query")!.Owner.ProductApp);
        Xunit.Assert.Same(SearchService.Instance, registry.Find("search.query")!.Owner.CloudServiceIdentity);
    }

    [Xunit.Fact]
    public void ProductOwnerFactoryBindsTheExactProductAndRejectsNull()
    {
        foreach (var app in new[] { AppIdentity.ArcScope, AppIdentity.Companion })
        {
            var owner = CapabilityOwner.Product(app);
            Xunit.Assert.Same(app, owner.ProductApp);
            Xunit.Assert.Null(owner.CloudServiceIdentity);
        }

        Xunit.Assert.Throws<ArgumentNullException>(() => CapabilityOwner.Product(null!));
    }

    private static void AssertMatches(ExpectedCapability expected, CapabilityRegistration registration)
    {
        Xunit.Assert.Equal(expected.Key, registration.Key);
        if (expected.OwnerKind == "Product")
        {
            Xunit.Assert.Equal(expected.Owner, registration.Owner.ProductApp!.ProductId);
            Xunit.Assert.Null(registration.Owner.CloudServiceIdentity);
        }
        else
        {
            Xunit.Assert.Equal("CloudService", expected.OwnerKind);
            Xunit.Assert.Equal("SearchService", expected.Owner);
            Xunit.Assert.Null(registration.Owner.ProductApp);
            Xunit.Assert.Same(SearchService.Instance, registration.Owner.CloudServiceIdentity);
        }

        var descriptor = registration.Descriptor;
        Xunit.Assert.Equal("1", descriptor.Version);
        Xunit.Assert.Equal(expected.RequestSchema, descriptor.RequestSchema);
        Xunit.Assert.Equal(expected.ResponseSchema, descriptor.ResponseSchema);
        Xunit.Assert.Equal(expected.Risk, descriptor.Risk);
        Xunit.Assert.Equal(expected.Locality, descriptor.Locality);
        Xunit.Assert.Equal(expected.Idempotency, descriptor.Idempotency);
        Xunit.Assert.Equal(expected.StatusOperation ?? string.Empty, descriptor.StatusOperation);
        Xunit.Assert.Equal(expected.StatusOperation is not null, descriptor.HasStatusOperation);
        Xunit.Assert.Empty(descriptor.Reads);
        Xunit.Assert.Empty(descriptor.Writes);
        Xunit.Assert.Equal(expected.Exclusive, descriptor.Exclusive);
        Xunit.Assert.Equal(expected.Egress, descriptor.Egress);
        Xunit.Assert.Equal(expected.Approval, descriptor.Approval);
        Xunit.Assert.Equal(expected.Execution, descriptor.Execution);
        Xunit.Assert.Equal(expected.Effect, descriptor.Effect);
        Xunit.Assert.Equal(expected.Retry, descriptor.Retry);
        Xunit.Assert.True(descriptor.HasCheckpoint);
        Xunit.Assert.False(descriptor.Checkpoint);
        Xunit.Assert.Empty(descriptor.AcceptedContext);
        Xunit.Assert.Null(descriptor.Preview);
        Xunit.Assert.Null(descriptor.Compensation);

        Xunit.Assert.True(descriptor.Binding.HasOperationId);
        Xunit.Assert.Equal(expected.Key, descriptor.Binding.OperationId);
        Xunit.Assert.True(descriptor.Binding.HasProtocol);
        Xunit.Assert.Equal(expected.Protocol, descriptor.Binding.Protocol);
        Xunit.Assert.True(descriptor.Binding.HasService);
        Xunit.Assert.Equal(expected.Service, descriptor.Binding.Service);
        Xunit.Assert.True(descriptor.Binding.HasMethod);
        Xunit.Assert.Equal(expected.Method, descriptor.Binding.Method);
        Xunit.Assert.True(descriptor.Binding.HasContractMajor);
        Xunit.Assert.Equal(1u, descriptor.Binding.ContractMajor);

        Xunit.Assert.True(descriptor.Cancel.HasAccepted);
        Xunit.Assert.True(descriptor.Cancel.Accepted);
        Xunit.Assert.True(descriptor.Cancel.HasBeforeDispatchOnly);
        Xunit.Assert.True(descriptor.Cancel.BeforeDispatchOnly);
        Xunit.Assert.False(descriptor.Cancel.HasStatusOperation);

        Xunit.Assert.True(descriptor.Limits.HasMaxInputBytes);
        Xunit.Assert.Equal(262_144ul, descriptor.Limits.MaxInputBytes);
        Xunit.Assert.True(descriptor.Limits.HasMaxOutputBytes);
        Xunit.Assert.Equal(262_144ul, descriptor.Limits.MaxOutputBytes);
        Xunit.Assert.True(descriptor.Limits.HasMaxDurationMs);
        Xunit.Assert.Equal(30_000ul, descriptor.Limits.MaxDurationMs);
        Xunit.Assert.True(descriptor.Limits.HasMaxConcurrency);
        Xunit.Assert.Equal(expected.MaxConcurrency, descriptor.Limits.MaxConcurrency);
        Xunit.Assert.True(descriptor.Limits.HasMaxContextItems);
        Xunit.Assert.Equal(50u, descriptor.Limits.MaxContextItems);
    }

    private sealed record ExpectedCapability(
        string Key,
        string OwnerKind,
        string Owner,
        string Service,
        string Method,
        string RequestSchema,
        string ResponseSchema,
        string Risk,
        string Approval,
        string Egress,
        string Idempotency,
        RetryMode Retry,
        EffectKind Effect,
        string? StatusOperation,
        BindingProtocol Protocol,
        ToolLocality Locality,
        ExecutionLocus Execution,
        bool Exclusive,
        uint MaxConcurrency);

    private sealed class EnumerationMustNotOccur<T> : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => throw new InvalidOperationException("Cloud catalogue metadata must not enumerate local targets.");

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Xunit.Fact]
    public void MissingDuplicateExtraUnsupportedAndMisclassifiedBindingsRefuse()
    {
        var registry = CapabilityRegistry.CreateInitial();
        var entries = registry.Registrations;
        var missing = Xunit.Assert.Throws<CapabilityRegistryException>(() =>
            CapabilityRegistry.ValidateInitial(entries.Skip(1)));
        Xunit.Assert.Equal(CapabilityRegistryFailure.MissingBinding, missing.Failure);

        var duplicate = Xunit.Assert.Throws<CapabilityRegistryException>(() =>
            CapabilityRegistry.ValidateInitial(entries.Concat([entries[0]])));
        Xunit.Assert.Equal(CapabilityRegistryFailure.DuplicateBinding, duplicate.Failure);

        var companion = registry.Find("IChatOperations.ListConversations")!;
        var wrongOwner = Xunit.Assert.Throws<CapabilityRegistryException>(() =>
            CapabilityRegistry.ValidateInitial(Replace(entries, companion.Key,
                new CapabilityRegistration(CapabilityOwner.Product(AppIdentity.ArcScope), companion.Descriptor))));
        Xunit.Assert.Equal(CapabilityRegistryFailure.MetadataMismatch, wrongOwner.Failure);

        var search = registry.Find("search.query")!;
        var cloudOwnerMasqueradingAsProduct = Xunit.Assert.Throws<CapabilityRegistryException>(() =>
            CapabilityRegistry.ValidateInitial(Replace(entries, search.Key,
                new CapabilityRegistration(CapabilityOwner.Product(AppIdentity.Companion), search.Descriptor))));
        Xunit.Assert.Equal(CapabilityRegistryFailure.MetadataMismatch, cloudOwnerMasqueradingAsProduct.Failure);

        var unknownDescriptor = entries[0].Descriptor;
        unknownDescriptor.Key = "IChatOperations.NotDeclared";
        unknownDescriptor.Binding.OperationId = unknownDescriptor.Key;
        var unexpected = Xunit.Assert.Throws<CapabilityRegistryException>(() =>
            CapabilityRegistry.ValidateInitial(entries.Concat([new CapabilityRegistration(entries[0].Owner, unknownDescriptor)])));
        Xunit.Assert.Equal(CapabilityRegistryFailure.UnexpectedBinding, unexpected.Failure);

        var read = registry.Find("IScopeOperations.GetSession")!;
        var missingCheckpoint = read.Descriptor;
        missingCheckpoint.ClearCheckpoint();
        var unspecifiedCheckpoint = Xunit.Assert.Throws<CapabilityRegistryException>(() =>
            CapabilityRegistry.ValidateInitial(Replace(entries, read.Key, new CapabilityRegistration(read.Owner, missingCheckpoint))));
        Xunit.Assert.Equal(CapabilityRegistryFailure.MetadataMismatch, unspecifiedCheckpoint.Failure);

        var unsupportedDescriptor = read.Descriptor;
        unsupportedDescriptor.Binding.ContractMajor = 2;
        var unsupported = Xunit.Assert.Throws<CapabilityRegistryException>(() =>
            CapabilityRegistry.ValidateInitial(Replace(entries, read.Key, new CapabilityRegistration(read.Owner, unsupportedDescriptor))));
        Xunit.Assert.Equal(CapabilityRegistryFailure.UnsupportedMajor, unsupported.Failure);

        var misclassifiedRead = read.Descriptor;
        misclassifiedRead.Writes.Add("not-an-authored-resource-key");
        var inconsistent = Xunit.Assert.Throws<CapabilityRegistryException>(() =>
            CapabilityRegistry.ValidateInitial(Replace(entries, read.Key, new CapabilityRegistration(read.Owner, misclassifiedRead))));
        Xunit.Assert.Equal(CapabilityRegistryFailure.InconsistentEffect, inconsistent.Failure);

        var mutation = registry.Find("IScopeOperations.CreateAnnotation")!;
        var nonExclusive = mutation.Descriptor;
        nonExclusive.Exclusive = false;
        var unsafeMutation = Xunit.Assert.Throws<CapabilityRegistryException>(() =>
            CapabilityRegistry.ValidateInitial(Replace(entries, mutation.Key, new CapabilityRegistration(mutation.Owner, nonExclusive))));
        Xunit.Assert.Equal(CapabilityRegistryFailure.InconsistentEffect, unsafeMutation.Failure);
    }

    [Xunit.Fact]
    public void RegistryOwnsClonedDescriptorsAndUsesFailSafeOwnerLevelWriteConcurrency()
    {
        var registry = CapabilityRegistry.CreateInitial();
        var registration = registry.Find("IScopeOperations.CreateAnnotation")!;
        var escaped = registration.Descriptor;
        escaped.Key = "corrupted";
        Xunit.Assert.Equal("IScopeOperations.CreateAnnotation", registry.Find("IScopeOperations.CreateAnnotation")!.Key);

        var pureRead = registry.Find("IScopeOperations.GetSession")!.Descriptor;
        Xunit.Assert.Equal(EffectKind.PureRead, pureRead.Effect);
        Xunit.Assert.Empty(pureRead.Writes);
        Xunit.Assert.False(pureRead.Exclusive);
        Xunit.Assert.Equal(4u, pureRead.Limits.MaxConcurrency);

        Xunit.Assert.Equal(1u, registration.Descriptor.Limits.MaxConcurrency);
        Xunit.Assert.True(registration.Descriptor.Exclusive);
        Xunit.Assert.Empty(registration.Descriptor.Reads);
        Xunit.Assert.Empty(registration.Descriptor.Writes);
    }

    [Xunit.Fact]
    public void OneReadyTargetIsSelectedAndUnavailableTargetReturnsTypedReason()
    {
        var registry = CapabilityRegistry.CreateInitial();
        var registration = registry.Find("IScopeOperations.ListSessions")!;
        var ready = Target(registration, seed: 1, InstanceHealth.Ready, acceptsWork: true);
        var busy = Target(registration, seed: 2, InstanceHealth.Busy, acceptsWork: true);

        var selected = CapabilitySelector.Select(registry, registration.Key, [busy, ready]);
        Xunit.Assert.True(selected.IsSelected);
        Xunit.Assert.Equal(ready.Identity, selected.Target!.Identity);
        Xunit.Assert.Contains("Exactly one eligible", selected.Explanation, StringComparison.Ordinal);

        var refusal = CapabilitySelector.Select(registry, registration.Key, [busy]);
        Xunit.Assert.Equal(CapabilitySelectionReason.NotReady, refusal.Reason);
        Xunit.Assert.Contains("Busy", refusal.Explanation, StringComparison.Ordinal);

        var notAccepting = Target(registration, seed: 7, InstanceHealth.Ready, acceptsWork: false);
        var admissionRefusal = CapabilitySelector.Select(registry, registration.Key, [notAccepting]);
        Xunit.Assert.Equal(CapabilitySelectionReason.NotReady, admissionRefusal.Reason);
        Xunit.Assert.Contains("refuses new work", admissionRefusal.Explanation, StringComparison.Ordinal);

        foreach (var health in new[] { InstanceHealth.Degraded, InstanceHealth.Draining, InstanceHealth.Unspecified })
        {
            var unhealthy = Target(registration, seed: 8 + (int)health, health, acceptsWork: true);
            var unhealthyRefusal = CapabilitySelector.Select(registry, registration.Key, [unhealthy]);
            Xunit.Assert.Equal(CapabilitySelectionReason.NotReady, unhealthyRefusal.Reason);
            Xunit.Assert.Contains(health.ToString(), unhealthyRefusal.Explanation, StringComparison.Ordinal);
        }
    }

    [Xunit.Fact]
    public void MultipleReadyTargetsRequireExplicitChoiceAndOrderIsStable()
    {
        var registry = CapabilityRegistry.CreateInitial();
        var registration = registry.Find("IScopeOperations.ListSessions")!;
        var first = Target(registration, seed: 3, InstanceHealth.Ready, acceptsWork: true);
        var second = Target(registration, seed: 4, InstanceHealth.Ready, acceptsWork: true);

        var reverse = CapabilitySelector.Select(registry, registration.Key, [second, first]);
        var forward = CapabilitySelector.Select(registry, registration.Key, [first, second]);
        Xunit.Assert.Equal(CapabilitySelectionReason.AmbiguousTarget, reverse.Reason);
        Xunit.Assert.Equal(reverse.ConsideredTargets, forward.ConsideredTargets);
        Xunit.Assert.Contains("user must select", reverse.Explanation, StringComparison.Ordinal);

        var chosen = CapabilitySelector.Select(registry, registration.Key, [second, first], explicitlySelectedTarget: second.Identity);
        Xunit.Assert.True(chosen.IsSelected);
        Xunit.Assert.Equal(second.Identity, chosen.Target!.Identity);
    }

    [Xunit.Fact]
    public void CapturedIdentityCannotBeRetargetedAndDescriptorVersionMustMatch()
    {
        var registry = CapabilityRegistry.CreateInitial();
        var registration = registry.Find("IScopeOperations.ListSessions")!;
        var first = Target(registration, seed: 5, InstanceHealth.Ready, acceptsWork: true);
        var second = Target(registration, seed: 6, InstanceHealth.Ready, acceptsWork: true);

        var retarget = CapabilitySelector.Select(registry, registration.Key, [first, second],
            capturedTarget: first.Identity, explicitlySelectedTarget: second.Identity);
        Xunit.Assert.Equal(CapabilitySelectionReason.RetargetingDenied, retarget.Reason);

        var staleDescriptor = registration.Descriptor;
        staleDescriptor.Binding.ContractMajor = 2;
        var incompatibleTarget = new CapabilityTarget(second.Identity, staleDescriptor, InstanceHealth.Ready, acceptsWork: true);
        var incompatible = CapabilitySelector.Select(registry, registration.Key, [incompatibleTarget]);
        Xunit.Assert.Equal(CapabilitySelectionReason.IncompatibleVersion, incompatible.Reason);
    }

    [Xunit.Fact]
    public void SelectorRefusesForeignOwnersAndDescriptorMismatches()
    {
        var registry = CapabilityRegistry.CreateInitial();
        var cloudChat = registry.Find("IChatOperations.ListConversations")!;
        var localScope = Target(registry.Find("IScopeOperations.ListSessions")!, seed: 9,
            InstanceHealth.Ready, acceptsWork: true);

        var foreignOwner = new CapabilityTarget(localScope.Identity, cloudChat.Descriptor,
            InstanceHealth.Ready, acceptsWork: true);
        var ownerRefusal = CapabilitySelector.Select(registry, cloudChat.Key, [foreignOwner]);
        Xunit.Assert.Equal(CapabilitySelectionReason.WrongOwner, ownerRefusal.Reason);

        var mismatchedDescriptor = cloudChat.Descriptor;
        mismatchedDescriptor.Risk = "R2";
        var descriptorMismatch = new CapabilityTarget(Target(cloudChat, seed: 10,
            InstanceHealth.Ready, acceptsWork: true).Identity, mismatchedDescriptor,
            InstanceHealth.Ready, acceptsWork: true);
        var mismatchRefusal = CapabilitySelector.Select(registry, cloudChat.Key, [descriptorMismatch]);
        Xunit.Assert.Equal(CapabilitySelectionReason.DescriptorMismatch, mismatchRefusal.Reason);
    }

    private static IEnumerable<CapabilityRegistration> Replace(
        IReadOnlyList<CapabilityRegistration> entries,
        string key,
        CapabilityRegistration replacement) =>
        entries.Where(entry => entry.Key != key).Append(replacement);

    private static CapabilityTarget Target(
        CapabilityRegistration registration,
        int seed,
        InstanceHealth health,
        bool acceptsWork)
    {
        var digits = seed.ToString("D12", System.Globalization.CultureInfo.InvariantCulture);
        var owner = registration.Owner.ProductApp
            ?? throw new InvalidOperationException("A local test target requires a Product owner.");
        var installation = new InstallationIdentity(owner,
            new ArcForges.Contracts.Foundation.Values.DeviceId(Guid.Parse($"10000000-0000-0000-0000-{digits}")),
            new ArcForges.Contracts.Foundation.Values.InstallationId(Guid.Parse($"20000000-0000-0000-0000-{digits}")));
        var identity = new InstanceIdentity(installation,
            new ArcForges.Contracts.Foundation.Values.InstanceId(Guid.Parse($"30000000-0000-0000-0000-{digits}")),
            (ulong)seed);
        return new CapabilityTarget(identity, registration.Descriptor, health, acceptsWork);
    }
}
