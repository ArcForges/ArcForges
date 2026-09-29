// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Contracts.PublicApi.V1;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Foundation.Execution;
using ArcForges.Sdk.Contracts.V1;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using SdkInvocation = ArcForges.Sdk.Contracts.V1.Invocation;
using WireRevision = ArcForges.Contracts.Foundation.V1.Revision;

namespace ArcForges.Capabilities.Tests;

public sealed class InvocationPipelineTests
{
    private const string CapabilityKey = "IScopeOperations.GetSession";
    private const string ActionKeyValue = "test.action.get-session";
    private static readonly string[] SuccessfulEvents =
    [
        "trace.started", "availability", "context.freeze", "authorize",
        "record.begin", "owner.invoke", "record.complete", "trace.completed",
    ];
    private static readonly CapabilityRegistry Registry = CapabilityRegistry.CreateInitial();
    private static readonly CapabilityRegistration Registration = Registry.Find(CapabilityKey)!;

    [Xunit.Fact]
    public async Task SuccessfulPipelinePreservesGeneratedRequestAndRunsInAuthorizedOrder()
    {
        var fixture = Fixture.Create();
        SdkInvocation? ownerRequest = null;
        FrozenContextSnapshot? ownerContext = null;
        var binding = Fixture.RevisionBinding((target, request, arguments, context, _) =>
        {
            fixture.Events.Add("owner.invoke");
            Xunit.Assert.Equal(fixture.Target.Identity, target.Identity);
            Xunit.Assert.Equal(7, request.ExpectedRev.Value);
            Xunit.Assert.Equal("argument", arguments);
            ownerRequest = request;
            ownerContext = context;
            request.ExpectedRev.Value = 99;
            return ValueTask.FromResult(Outcome.Success(new OwnerResult("response", new WireRevision { Value = 12 })));
        });
        var pipeline = fixture.Pipeline(binding);
        var request = fixture.Request();

        var result = await pipeline.InvokeAsync(
            request, new ActionKey(ActionKeyValue), fixture.AvailabilityContext,
            [fixture.Target], [fixture.ContextProvider], capturedTarget: fixture.Target.Identity,
            cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal(OutcomeKind.Success, result.Kind);
        var value = Xunit.Assert.IsType<CapabilityInvocationValue>(result.Value);
        Xunit.Assert.Equal("response", value.Result.Value.Text);
        Xunit.Assert.Equal(InvocationResultVersionKind.Revision, value.Version.Kind);
        Xunit.Assert.Equal(12, value.Version.Revision!.Value);
        var returnedResult = value.Result;
        returnedResult.Value.Text = "caller mutation";
        var returnedVersion = value.Version.Revision!;
        returnedVersion.Value = 77;
        Xunit.Assert.Equal("response", value.Result.Value.Text);
        Xunit.Assert.Equal(12, value.Version.Revision!.Value);
        Xunit.Assert.NotNull(ownerRequest);
        Xunit.Assert.NotSame(fixture.LastRequest, ownerRequest);
        Xunit.Assert.Equal(7, request.ExpectedRev.Value);
        Xunit.Assert.Equal(fixture.Target.Identity, ownerContext!.Owner);
        Xunit.Assert.Equal(StringValue.Descriptor.FullName, ownerContext.Items.Single().TypeName);
        Xunit.Assert.Equal(
            SuccessfulEvents,
            fixture.Events);
        Xunit.Assert.Equal(2, fixture.Trace.Records.Count);
        Xunit.Assert.Equal(InvocationTracePhase.Started, fixture.Trace.Records[0].Phase);
        Xunit.Assert.Equal(InvocationTracePhase.Completed, fixture.Trace.Records[1].Phase);
        Xunit.Assert.Equal(CapabilityKey, fixture.Trace.Records[1].CapabilityKey);
        Xunit.Assert.Equal(InvocationResultVersionKind.Revision, fixture.Trace.Records[1].ResultVersionKind);
        Xunit.Assert.Null(fixture.Trace.Records[1].FailureCode);
    }

    [Xunit.Fact]
    public async Task UnregisteredCapabilityCanaryIsNeverCopiedToTrace()
    {
        var canary = string.Concat("secret-canary", (char)0x01, "unregistered");
        Xunit.Assert.Equal((char)0x01, canary["secret-canary".Length]);
        var fixture = Fixture.Create();
        var ownerCalls = 0;
        var pipeline = fixture.Pipeline(Fixture.RevisionBinding((_, _, arguments, _, _) =>
        {
            ownerCalls++;
            return ValueTask.FromResult(Outcome.Success(new OwnerResult(arguments, new WireRevision { Value = 12 })));
        }));
        var request = fixture.Request();
        request.Capability = canary;

        var result = await pipeline.InvokeAsync(request, new ActionKey(ActionKeyValue), fixture.AvailabilityContext,
            [fixture.Target], [fixture.ContextProvider], capturedTarget: fixture.Target.Identity,
            cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal(OutcomeKind.Failure, result.Kind);
        Xunit.Assert.Equal("validation.invalid_request", result.Failure!.Code);
        Xunit.Assert.Equal(0, ownerCalls);
        Xunit.Assert.Equal(2, fixture.Trace.Records.Count);
        Xunit.Assert.All(fixture.Trace.Records, record => Xunit.Assert.Null(record.CapabilityKey));
        Xunit.Assert.DoesNotContain(canary, fixture.Trace.Records.Select(record => record.CapabilityKey ?? string.Empty));
    }

    [Xunit.Fact]
    public async Task SameCommandReplayRechecksAvailabilityContextAndAuthorizationButDoesNotInvokeAgain()
    {
        var fixture = Fixture.Create();
        var ownerCalls = 0;
        var binding = Fixture.RevisionBinding((_, _, arguments, _, _) =>
        {
            fixture.Events.Add("owner.invoke");
            ownerCalls++;
            return ValueTask.FromResult(Outcome.Success(new OwnerResult(arguments, new WireRevision { Value = 12 })));
        });
        var pipeline = fixture.Pipeline(binding);
        var request = fixture.Request();

        var first = await pipeline.InvokeAsync(request, new ActionKey(ActionKeyValue), fixture.AvailabilityContext,
            [fixture.Target], [fixture.ContextProvider], capturedTarget: fixture.Target.Identity,
            cancellationToken: Xunit.TestContext.Current.CancellationToken);
        var retry = request.Clone();
        retry.InvocationId = InvocationId.New().ToWire();
        var replay = await pipeline.InvokeAsync(retry, new ActionKey(ActionKeyValue), fixture.AvailabilityContext,
            [fixture.Target], [fixture.ContextProvider], capturedTarget: fixture.Target.Identity,
            cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal(OutcomeKind.Success, first.Kind);
        Xunit.Assert.Equal(OutcomeKind.Success, replay.Kind);
        Xunit.Assert.Equal("argument", replay.Value!.Result.Value.Text);
        Xunit.Assert.Equal(2, fixture.Availability.Calls);
        Xunit.Assert.Equal(2, fixture.ContextCalls);
        Xunit.Assert.Equal(2, fixture.AuthorizationCalls);
        Xunit.Assert.Equal(1, ownerCalls);
        Xunit.Assert.Equal(2, fixture.RecordStore.BeginCalls);
        Xunit.Assert.Equal(1, fixture.RecordStore.CompleteCalls);
    }

    [Xunit.Fact]
    public async Task ReusingCommandIdForDifferentRequestFingerprintIsRefused()
    {
        var fixture = Fixture.Create();
        var ownerCalls = 0;
        var pipeline = fixture.Pipeline(Fixture.RevisionBinding((_, _, arguments, _, _) =>
        {
            ownerCalls++;
            return ValueTask.FromResult(Outcome.Success(new OwnerResult(arguments, new WireRevision { Value = 12 })));
        }));
        var request = fixture.Request();

        var first = await pipeline.InvokeAsync(request, new ActionKey(ActionKeyValue), fixture.AvailabilityContext,
            [fixture.Target], [fixture.ContextProvider], capturedTarget: fixture.Target.Identity,
            cancellationToken: Xunit.TestContext.Current.CancellationToken);
        var conflictingRequest = request.Clone();
        conflictingRequest.Arguments.Value.Text = "different command content";
        var conflict = await pipeline.InvokeAsync(conflictingRequest, new ActionKey(ActionKeyValue), fixture.AvailabilityContext,
            [fixture.Target], [fixture.ContextProvider], capturedTarget: fixture.Target.Identity,
            cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal(OutcomeKind.Success, first.Kind);
        Xunit.Assert.Equal("validation.invalid_request", conflict.Failure!.Code);
        Xunit.Assert.Equal(2, fixture.AuthorizationCalls);
        Xunit.Assert.Equal(1, ownerCalls);
        Xunit.Assert.Equal(1, fixture.RecordStore.CompleteCalls);
    }

    [Xunit.Fact]
    public async Task AnActionCannotInvokeACapabilityItDoesNotDeclare()
    {
        var fixture = Fixture.Create();
        fixture.Availability.IsBound = false;
        var ownerCalls = 0;
        var pipeline = fixture.Pipeline(Fixture.RevisionBinding((_, _, _, _, _) =>
        {
            ownerCalls++;
            return ValueTask.FromResult(Outcome.Success(new OwnerResult("response", new WireRevision { Value = 12 })));
        }));

        var result = await pipeline.InvokeAsync(fixture.Request(), new ActionKey(ActionKeyValue),
            fixture.AvailabilityContext, [fixture.Target], [fixture.ContextProvider],
            capturedTarget: fixture.Target.Identity, cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal("validation.invalid_request", result.Failure!.Code);
        Xunit.Assert.Equal(0, fixture.RecordStore.BeginCalls);
        Xunit.Assert.Equal(0, fixture.AuthorizationCalls);
        Xunit.Assert.Equal(0, ownerCalls);
    }

    [Xunit.Fact]
    public async Task AvailabilityAndAuthorizationFailuresFailClosedBeforeRecordingOrOwnerDispatch()
    {
        var unavailable = Fixture.Create();
        unavailable.Availability.Result = AvailabilityResult.PermissionRequired;
        var unavailableOwnerCalls = 0;
        var unavailablePipeline = unavailable.Pipeline(Fixture.RevisionBinding((_, _, _, _, _) =>
        {
            unavailableOwnerCalls++;
            return ValueTask.FromResult(Outcome.Success(new OwnerResult("response", new WireRevision { Value = 12 })));
        }));

        var unavailableResult = await unavailablePipeline.InvokeAsync(unavailable.Request(), new ActionKey(ActionKeyValue),
            unavailable.AvailabilityContext, [unavailable.Target], [unavailable.ContextProvider],
            capturedTarget: unavailable.Target.Identity, cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal("perm.capability_denied", unavailableResult.Failure!.Code);
        Xunit.Assert.Equal(0, unavailable.RecordStore.BeginCalls);
        Xunit.Assert.Equal(0, unavailable.AuthorizationCalls);
        Xunit.Assert.Equal(0, unavailableOwnerCalls);

        var denied = Fixture.Create();
        denied.Authorize = (_, _, _, _, _) =>
        {
            denied.Events.Add("authorize");
            denied.AuthorizationCalls++;
            return ValueTask.FromResult(Outcome.Success(false));
        };
        var deniedOwnerCalls = 0;
        var deniedPipeline = denied.Pipeline(Fixture.RevisionBinding((_, _, _, _, _) =>
        {
            deniedOwnerCalls++;
            return ValueTask.FromResult(Outcome.Success(new OwnerResult("response", new WireRevision { Value = 12 })));
        }));

        var deniedResult = await deniedPipeline.InvokeAsync(denied.Request(), new ActionKey(ActionKeyValue),
            denied.AvailabilityContext, [denied.Target], [denied.ContextProvider],
            capturedTarget: denied.Target.Identity, cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal("perm.capability_denied", deniedResult.Failure!.Code);
        Xunit.Assert.Equal(0, denied.RecordStore.BeginCalls);
        Xunit.Assert.Equal(0, deniedOwnerCalls);
    }

    [Xunit.Fact]
    public async Task VersionedOwnerSuccessCannotClaimNonVersionedOrMissingRevision()
    {
        foreach (var version in new Func<OwnerResult, InvocationResultVersion>[]
        {
            _ => InvocationResultVersion.NonVersioned(),
            _ => InvocationResultVersion.FromRevision(new WireRevision()),
        })
        {
            var fixture = Fixture.Create();
            var binding = Fixture.RevisionBinding(
                (_, _, _, _, _) => ValueTask.FromResult(Outcome.Success(new OwnerResult("response", new WireRevision { Value = 12 }))),
                version);
            var pipeline = fixture.Pipeline(binding);

            var result = await pipeline.InvokeAsync(fixture.Request(), new ActionKey(ActionKeyValue),
                fixture.AvailabilityContext, [fixture.Target], [fixture.ContextProvider],
                capturedTarget: fixture.Target.Identity, cancellationToken: Xunit.TestContext.Current.CancellationToken);

            Xunit.Assert.Equal("internal.unexpected", result.Failure!.Code);
            Xunit.Assert.Equal(1, fixture.RecordStore.CompleteCalls);
        }
    }

    [Xunit.Fact]
    public async Task NonVersionedHandleSuccessHasNoRevisionPayloadAndNativeRevisionStaysNative()
    {
        var nonVersioned = Fixture.Create();
        var handleBinding = new CapabilityInvocationBinding<string, string>(
            Registry,
            CapabilityKey,
            InvocationResultVersionKind.NonVersioned,
            DecodeText,
            (_, _, value, _, _) => ValueTask.FromResult(Outcome.Success(value)),
            EncodeText,
            _ => InvocationResultVersion.NonVersioned());
        var handlePipeline = nonVersioned.Pipeline(handleBinding);
        var handle = await handlePipeline.InvokeAsync(nonVersioned.Request(), new ActionKey(ActionKeyValue),
            nonVersioned.AvailabilityContext, [nonVersioned.Target], [nonVersioned.ContextProvider],
            capturedTarget: nonVersioned.Target.Identity, cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal(OutcomeKind.Success, handle.Kind);
        Xunit.Assert.Equal(InvocationResultVersionKind.NonVersioned, handle.Value!.Version.Kind);
        Xunit.Assert.Null(handle.Value.Version.Revision);
        Xunit.Assert.Null(handle.Value.Version.NativeContentRev);

        var revision = InvocationResultVersion.FromRevision(new WireRevision { Value = 13 });
        var native = InvocationResultVersion.FromNativeContentRev(new NativeContentRev { Value = 13 });
        Xunit.Assert.Equal(InvocationResultVersionKind.Revision, revision.Kind);
        Xunit.Assert.Equal(13, revision.Revision!.Value);
        Xunit.Assert.Equal(InvocationResultVersionKind.NativeContentRev, native.Kind);
        Xunit.Assert.Equal(13ul, native.NativeContentRev!.Value);
        Xunit.Assert.Throws<ArgumentException>(() => InvocationResultVersion.FromRevision(new WireRevision { Value = 0 }));
        Xunit.Assert.Throws<ArgumentException>(() => InvocationResultVersion.FromNativeContentRev(new NativeContentRev { Value = 0 }));

        var nativeFixture = Fixture.Create();
        var nativeBinding = new CapabilityInvocationBinding<string, NativeOwnerResult>(
            Registry,
            CapabilityKey,
            InvocationResultVersionKind.NativeContentRev,
            DecodeText,
            (_, _, value, _, _) => ValueTask.FromResult(Outcome.Success(new NativeOwnerResult(value, new NativeContentRev { Value = 13 }))),
            result => Outcome.Success(new CapabilityResult
            {
                SchemaId = Registration.Descriptor.ResponseSchema,
                Value = new StructuredValue { Text = result.Value },
            }),
            result => InvocationResultVersion.FromNativeContentRev(result.Revision));
        var nativePipeline = nativeFixture.Pipeline(nativeBinding);
        var nativeOutcome = await nativePipeline.InvokeAsync(nativeFixture.Request(), new ActionKey(ActionKeyValue),
            nativeFixture.AvailabilityContext, [nativeFixture.Target], [nativeFixture.ContextProvider],
            capturedTarget: nativeFixture.Target.Identity, cancellationToken: Xunit.TestContext.Current.CancellationToken);
        Xunit.Assert.Equal(OutcomeKind.Success, nativeOutcome.Kind);
        Xunit.Assert.Equal(InvocationResultVersionKind.NativeContentRev, nativeOutcome.Value!.Version.Kind);
        Xunit.Assert.Equal(13ul, nativeOutcome.Value.Version.NativeContentRev!.Value);
    }

    [Xunit.Fact]
    public async Task ContextOwnerMismatchAndRequestBudgetAreRefusedBeforeAuthorization()
    {
        var foreign = Fixture.Create();
        var foreignIdentity = CreateIdentity(AppIdentity.Companion);
        var foreignProvider = new ContextProvider<StringValue>(foreignIdentity,
            (_, _) => ValueTask.FromResult<IReadOnlyList<StringValue>>([new StringValue { Value = "foreign" }]));
        var foreignPipeline = foreign.Pipeline(Fixture.RevisionBinding((_, _, _, _, _) =>
            ValueTask.FromResult(Outcome.Success(new OwnerResult("response", new WireRevision { Value = 12 })))));

        var mismatch = await foreignPipeline.InvokeAsync(foreign.Request(), new ActionKey(ActionKeyValue),
            foreign.AvailabilityContext, [foreign.Target], [foreignProvider],
            capturedTarget: foreign.Target.Identity, cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal("perm.capability_denied", mismatch.Failure!.Code);
        Xunit.Assert.Equal(0, foreign.AuthorizationCalls);
        Xunit.Assert.Equal(0, foreign.RecordStore.BeginCalls);

        var large = Fixture.Create();
        var largeRequest = large.Request();
        largeRequest.Arguments.Value.Text = new string('x', 262_144);
        var largePipeline = large.Pipeline(Fixture.RevisionBinding((_, _, _, _, _) =>
            ValueTask.FromResult(Outcome.Success(new OwnerResult("response", new WireRevision { Value = 12 })))));
        var tooLarge = await largePipeline.InvokeAsync(largeRequest, new ActionKey(ActionKeyValue),
            large.AvailabilityContext, [large.Target], [large.ContextProvider],
            capturedTarget: large.Target.Identity, cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal("entitlement.request_too_large", tooLarge.Failure!.Code);
        Xunit.Assert.Equal(0, large.RecordStore.BeginCalls);
        Xunit.Assert.Equal(0, large.AuthorizationCalls);
    }

    [Xunit.Fact]
    public async Task TraceStartFailureStopsAllSensitiveAndMutatingWork()
    {
        var fixture = Fixture.Create();
        fixture.Trace.FailFirst = true;
        var ownerCalls = 0;
        var pipeline = fixture.Pipeline(Fixture.RevisionBinding((_, _, _, _, _) =>
        {
            ownerCalls++;
            return ValueTask.FromResult(Outcome.Success(new OwnerResult("response", new WireRevision { Value = 12 })));
        }));

        var result = await pipeline.InvokeAsync(fixture.Request(), new ActionKey(ActionKeyValue),
            fixture.AvailabilityContext, [fixture.Target], [fixture.ContextProvider],
            capturedTarget: fixture.Target.Identity, cancellationToken: Xunit.TestContext.Current.CancellationToken);

        Xunit.Assert.Equal("internal.unexpected", result.Failure!.Code);
        Xunit.Assert.Equal(0, fixture.Availability.Calls);
        Xunit.Assert.Equal(0, fixture.AuthorizationCalls);
        Xunit.Assert.Equal(0, fixture.RecordStore.BeginCalls);
        Xunit.Assert.Equal(0, ownerCalls);
    }

    [Xunit.Fact]
    public async Task OwnerCancellationAndExceptionsCloseTheClaimAndCompleteTrace()
    {
        var cancelled = Fixture.Create();
        var cancelBinding = new CapabilityInvocationBinding<string, string>(
            Registry,
            CapabilityKey,
            InvocationResultVersionKind.NonVersioned,
            DecodeText,
            (_, _, _, _, _) => ValueTask.FromResult(Outcome.Cancelled<string>(EffectCertainty.Unknown)),
            EncodeText,
            _ => InvocationResultVersion.NonVersioned());
        var cancelledResult = await cancelled.Pipeline(cancelBinding).InvokeAsync(cancelled.Request(),
            new ActionKey(ActionKeyValue), cancelled.AvailabilityContext, [cancelled.Target], [cancelled.ContextProvider],
            capturedTarget: cancelled.Target.Identity, cancellationToken: Xunit.TestContext.Current.CancellationToken);
        Xunit.Assert.Equal(OutcomeKind.Cancelled, cancelledResult.Kind);
        Xunit.Assert.Equal(EffectCertainty.Unknown, cancelledResult.CancellationEffect);
        Xunit.Assert.Equal(1, cancelled.RecordStore.CompleteCalls);
        Xunit.Assert.Equal(InvocationTracePhase.Completed, cancelled.Trace.Records[^1].Phase);

        var faulted = Fixture.Create();
        var faultedResult = await faulted.Pipeline(new CapabilityInvocationBinding<string, string>(
            Registry,
            CapabilityKey,
            InvocationResultVersionKind.NonVersioned,
            DecodeText,
            (_, _, _, _, _) => throw new InvalidOperationException("owner adapter failure"),
            EncodeText,
            _ => InvocationResultVersion.NonVersioned())).InvokeAsync(faulted.Request(), new ActionKey(ActionKeyValue),
            faulted.AvailabilityContext, [faulted.Target], [faulted.ContextProvider],
            capturedTarget: faulted.Target.Identity, cancellationToken: Xunit.TestContext.Current.CancellationToken);
        Xunit.Assert.Equal("internal.unexpected", faultedResult.Failure!.Code);
        Xunit.Assert.Equal(1, faulted.RecordStore.CompleteCalls);
        Xunit.Assert.Equal(InvocationTracePhase.Completed, faulted.Trace.Records[^1].Phase);
    }

    [Xunit.Fact]
    public void PipelineIsTheOnlyPublicInvocationRoute()
    {
        var pipelineMethods = typeof(CapabilityInvocationPipeline).GetMethods(
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.DeclaredOnly);
        Xunit.Assert.Equal(nameof(CapabilityInvocationPipeline.InvokeAsync), Xunit.Assert.Single(pipelineMethods).Name);

        var bindingMethods = typeof(CapabilityInvocationBinding).GetMethods(
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.DeclaredOnly);
        Xunit.Assert.DoesNotContain(bindingMethods, method => method.Name == "InvokeAsync");
    }

    [Xunit.Fact]
    public void FailureMappingsCoverEveryDefinedSelectionAndAvailabilityValue()
    {
        var selection = new Dictionary<CapabilitySelectionReason, string>
        {
            [CapabilitySelectionReason.None] = "internal.unexpected",
            [CapabilitySelectionReason.CapabilityNotRegistered] = "validation.invalid_request",
            [CapabilitySelectionReason.TargetUnavailable] = "dependency.unavailable",
            [CapabilitySelectionReason.IncompatibleVersion] = "validation.unsupported_version",
            [CapabilitySelectionReason.NotReady] = "dependency.unavailable",
            [CapabilitySelectionReason.AmbiguousTarget] = "validation.invalid_request",
            [CapabilitySelectionReason.DescriptorMismatch] = "validation.invalid_request",
            [CapabilitySelectionReason.RetargetingDenied] = "perm.capability_denied",
            [CapabilitySelectionReason.WrongOwner] = "perm.capability_denied",
            [CapabilitySelectionReason.CloudServiceNotLocalTarget] = "dependency.unavailable",
        };
        Xunit.Assert.Equal(System.Enum.GetValues<CapabilitySelectionReason>(), selection.Keys.Order());
        foreach (var pair in selection)
        {
            Xunit.Assert.Equal(pair.Value, InvocationFailureMap.FromSelection(pair.Key));
            Xunit.Assert.True(TypedFailure.Create(InvocationFailureMap.FromSelection(pair.Key)).IsKnownCode);
        }

        var availability = new Dictionary<AvailabilityResult, string>
        {
            [AvailabilityResult.Available] = "internal.unexpected",
            [AvailabilityResult.NotApplicableToContext] = "validation.invalid_request",
            [AvailabilityResult.AppNotInstalled] = "state.not_found",
            [AvailabilityResult.AppNotRunning] = "state.gone",
            [AvailabilityResult.IncompatibleVersion] = "validation.unsupported_version",
            [AvailabilityResult.PermissionRequired] = "perm.capability_denied",
            [AvailabilityResult.EntitlementRequired] = "entitlement.not_entitled",
            [AvailabilityResult.PolicyDisabled] = "perm.capability_denied",
            [AvailabilityResult.TemporarilyUnavailable] = "dependency.unavailable",
        };
        Xunit.Assert.Equal(System.Enum.GetValues<AvailabilityResult>(), availability.Keys.Order());
        foreach (var pair in availability)
        {
            Xunit.Assert.Equal(pair.Value, InvocationFailureMap.FromAvailability(pair.Key));
            Xunit.Assert.True(TypedFailure.Create(InvocationFailureMap.FromAvailability(pair.Key)).IsKnownCode);
        }

        Xunit.Assert.Equal("internal.unexpected", InvocationFailureMap.FromAvailability((AvailabilityResult)99));
        Xunit.Assert.Equal("internal.unexpected", InvocationFailureMap.FromSelection((CapabilitySelectionReason)99));
    }

    [Xunit.Fact]
    public async Task InvocationOutcomeFactoriesPreserveTheirDistinctTypedArms()
    {
        var fixture = Fixture.Create();
        var value = await fixture.Pipeline(Fixture.RevisionBinding((_, _, arguments, _, _) =>
            ValueTask.FromResult(Outcome.Success(new OwnerResult(arguments, new WireRevision { Value = 12 }))))).InvokeAsync(
                fixture.Request(), new ActionKey(ActionKeyValue), fixture.AvailabilityContext,
                [fixture.Target], [fixture.ContextProvider], capturedTarget: fixture.Target.Identity,
                cancellationToken: Xunit.TestContext.Current.CancellationToken);

        var success = InvocationOutcome.Success(Xunit.Assert.IsType<CapabilityInvocationValue>(value.Value));
        var failure = InvocationOutcome.FailureResult(TypedFailure.Create("validation.invalid_request"));
        var cancelled = InvocationOutcome.Cancelled(EffectCertainty.Unknown);

        Xunit.Assert.Equal(OutcomeKind.Success, success.Kind);
        Xunit.Assert.Equal(12, success.Value!.Version.Revision!.Value);
        Xunit.Assert.Equal(OutcomeKind.Failure, failure.Kind);
        Xunit.Assert.Equal("validation.invalid_request", failure.Failure!.Code);
        Xunit.Assert.Equal(OutcomeKind.Cancelled, cancelled.Kind);
        Xunit.Assert.Equal(EffectCertainty.Unknown, cancelled.CancellationEffect);
    }

    [Xunit.Fact]
    public void RecordClaimFactoriesRequireAnExecutionReservationOrRecordedOutcome()
    {
        var reservation = Guid.NewGuid();
        var execution = InvocationRecordClaim.ForExecution(reservation);
        var recorded = InvocationOutcome.FailureResult(TypedFailure.Create("validation.invalid_request"));
        var replay = InvocationRecordClaim.ForReplay(recorded);

        Xunit.Assert.Equal(InvocationRecordClaimKind.Execute, execution.Kind);
        Xunit.Assert.Equal(reservation, execution.ReservationId);
        Xunit.Assert.Null(execution.ReplayOutcome);
        Xunit.Assert.Equal(InvocationRecordClaimKind.Replay, replay.Kind);
        Xunit.Assert.Equal(recorded, replay.ReplayOutcome);
        Xunit.Assert.Throws<ArgumentException>(() => InvocationRecordClaim.ForExecution(Guid.Empty));
    }

    private static Outcome<string> DecodeText(CapabilityArguments arguments) =>
        arguments.Value.ValueCase == StructuredValue.ValueOneofCase.Text
            ? Outcome.Success(arguments.Value.Text)
            : Outcome.Failure<string>(TypedFailure.Create("validation.invalid_request"));

    private static Outcome<CapabilityResult> EncodeText(string value) => Outcome.Success(new CapabilityResult
    {
        SchemaId = Registration.Descriptor.ResponseSchema,
        Value = new StructuredValue { Text = value },
    });

    private static InstanceIdentity CreateIdentity(AppIdentity app) => new(
        new InstallationIdentity(app,
            new DeviceId(new Guid("10000000-0000-0000-0000-000000000001")),
            new InstallationId(new Guid("20000000-0000-0000-0000-000000000001"))),
        new InstanceId(new Guid(app.ProductId == "arcscope"
            ? "30000000-0000-0000-0000-000000000001"
            : "40000000-0000-0000-0000-000000000001")),
        1);

    private sealed record OwnerResult(string Value, WireRevision Revision);
    private sealed record NativeOwnerResult(string Value, NativeContentRev Revision);

    private sealed class Fixture
    {
        private Fixture()
        {
            Target = new CapabilityTarget(Identity, Registration.Descriptor, InstanceHealth.Ready, acceptsWork: true);
            AvailabilityContext = FrozenContextSnapshot.Freeze(Identity, [new StringValue { Value = "available" }], ContextSnapshotBudget.Default);
            ContextProvider = new ContextProvider<StringValue>(Identity, (_, _) =>
            {
                ContextCalls++;
                Events.Add("context.freeze");
                return ValueTask.FromResult<IReadOnlyList<StringValue>>([new StringValue { Value = "invocation" }]);
            });
            Trace = new RecordingTrace(Events);
            RecordStore = new RecordingRecordStore(Events);
            Availability = new RecordingAvailability(Events);
            Authorize = (_, _, target, context, _) =>
            {
                Events.Add("authorize");
                AuthorizationCalls++;
                Xunit.Assert.Equal(Target.Identity, target.Identity);
                Xunit.Assert.Equal(Target.Identity, context.Owner);
                return ValueTask.FromResult(Outcome.Success(true));
            };
        }

        public static Fixture Create() => new();

        public InstanceIdentity Identity { get; } = CreateIdentity(AppIdentity.ArcScope);
        public CapabilityTarget Target { get; }
        public FrozenContextSnapshot AvailabilityContext { get; }
        public ContextProvider<StringValue> ContextProvider { get; }
        public RecordingAvailability Availability { get; }
        public RecordingRecordStore RecordStore { get; }
        public RecordingTrace Trace { get; }
        public List<string> Events { get; } = [];
        public int ContextCalls { get; set; }
        public int AuthorizationCalls { get; set; }
        public CapabilityInvocationAuthorization Authorize { get; set; }
        public SdkInvocation? LastRequest { get; private set; }

        public SdkInvocation Request()
        {
            var request = new SdkInvocation
            {
                InvocationId = InvocationId.New().ToWire(),
                CommandId = InvocationId.New().ToWire(),
                Capability = CapabilityKey,
                Context = new FrozenContext { ProfileVersion = "profile.7", PermissionsVersion = "permission.12" },
                Arguments = new CapabilityArguments
                {
                    SchemaId = Registration.Descriptor.RequestSchema,
                    Value = new StructuredValue { Text = "argument" },
                },
                ExpectedRev = new WireRevision { Value = 7 },
            };
            LastRequest = request;
            return request;
        }

        public static CapabilityInvocationBinding<string, OwnerResult> RevisionBinding(
            CapabilityOwnerOperation<string, OwnerResult> invoke,
            Func<OwnerResult, InvocationResultVersion>? version = null) => new(
                Registry,
                CapabilityKey,
                InvocationResultVersionKind.Revision,
                DecodeText,
                invoke,
                result => Outcome.Success(new CapabilityResult
                {
                    SchemaId = Registration.Descriptor.ResponseSchema,
                    Value = new StructuredValue { Text = result.Value },
                }),
                version ?? (result => InvocationResultVersion.FromRevision(result.Revision)));

        public CapabilityInvocationPipeline Pipeline(CapabilityInvocationBinding binding) => new(
            Registry,
            Availability,
            [binding],
            (registration, invocation, target, context, cancellationToken) => Authorize(
                registration, invocation, target, context, cancellationToken),
            RecordStore,
            Trace);
    }

    private sealed class RecordingAvailability(List<string> events) : ICapabilityProvider
    {
        public AvailabilityResult Result { get; set; } = AvailabilityResult.Available;
        public bool IsBound { get; set; } = true;
        public int Calls { get; private set; }

        public bool IsBoundToCapability(ActionKey actionKey, string capabilityKey) =>
            IsBound && actionKey.Value == ActionKeyValue && capabilityKey == CapabilityKey;

        public ValueTask<Outcome<AvailabilityResult>> EvaluateAvailabilityAsync(
            ActionKey actionKey,
            FrozenContextSnapshot context,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            events.Add("availability");
            return ValueTask.FromResult(Outcome.Success(Result));
        }
    }

    private sealed class RecordingRecordStore(List<string> events) : IInvocationRecordStore
    {
        private readonly Dictionary<string, StoredInvocation> _completed = new(StringComparer.Ordinal);
        private readonly Dictionary<Guid, PendingInvocation> _pending = [];

        public int BeginCalls { get; private set; }
        public int CompleteCalls { get; private set; }

        public ValueTask<Outcome<InvocationRecordClaim>> BeginAsync(Id commandId, ByteString requestFingerprint, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            BeginCalls++;
            events.Add("record.begin");
            var commandKey = commandId.Value.ToBase64();
            if (_completed.TryGetValue(commandKey, out var previous))
            {
                return previous.Fingerprint.Equals(requestFingerprint)
                    ? ValueTask.FromResult(Outcome.Success(InvocationRecordClaim.ForReplay(previous.Outcome)))
                    : ValueTask.FromResult(Outcome.Failure<InvocationRecordClaim>(TypedFailure.Create("validation.invalid_request")));
            }

            var reservationId = Guid.NewGuid();
            _pending.Add(reservationId, new PendingInvocation(commandKey, requestFingerprint));
            return ValueTask.FromResult(Outcome.Success(InvocationRecordClaim.ForExecution(reservationId)));
        }

        public ValueTask<Outcome<InvocationOutcome>> CompleteAsync(
            InvocationRecordClaim claim,
            InvocationOutcome outcome,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CompleteCalls++;
            events.Add("record.complete");
            if (claim.Kind != InvocationRecordClaimKind.Execute || !_pending.Remove(claim.ReservationId, out var pending))
            {
                return ValueTask.FromResult(Outcome.Failure<InvocationOutcome>(TypedFailure.Create("internal.unexpected")));
            }

            _completed.Add(pending.CommandKey, new StoredInvocation(pending.Fingerprint, outcome));
            return ValueTask.FromResult(Outcome.Success(outcome));
        }

        private sealed record PendingInvocation(string CommandKey, ByteString Fingerprint);
        private sealed record StoredInvocation(ByteString Fingerprint, InvocationOutcome Outcome);
    }

    private sealed class RecordingTrace(List<string> events) : IInvocationTraceSink
    {
        public List<InvocationTraceRecord> Records { get; } = [];
        public bool FailFirst { get; set; }

        public ValueTask<Outcome<bool>> WriteAsync(InvocationTraceRecord record, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Records.Add(record);
            var isStart = record.Phase == InvocationTracePhase.Started;
            events.Add(isStart ? "trace.started" : "trace.completed");
            if (FailFirst && isStart)
            {
                return ValueTask.FromResult(Outcome.Failure<bool>(TypedFailure.Create("internal.unexpected")));
            }

            return ValueTask.FromResult(Outcome.Success(true));
        }
    }
}
