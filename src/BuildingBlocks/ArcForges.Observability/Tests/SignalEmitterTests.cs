// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Reflection;
using ArcForges.Capabilities;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Foundation.Execution;
using Xunit;

namespace ArcForges.Observability.Tests;

public sealed class SignalEmitterTests
{
    [Fact]
    public void OneEmissionCarriesEveryPresentDimensionToTraceAndStructuredEvent()
    {
        var context = new ObservabilityContext(SignalApplicationDimension.ArcScope, new InstanceId(Guid.NewGuid()), SignalEnvironment.Test)
        {
            ActorReference = "sha256:" + new string('a', 64),
            Workspace = new WorkspaceId(Guid.NewGuid()),
            Transport = SignalTransport.LocalRpc,
            Service = SignalService.Storage,
            Interface = SignalInterface.ResourceStore,
            Method = SignalMethod.Commit,
            Capability = SignalCapability.ResourceWrite,
            RedactedResourceReference = "sha256:" + new string('b', 64),
            Command = new CommandId(Guid.NewGuid()),
            Task = TaskId.New(),
            Run = RunId.New(),
            Attempt = AttemptId.New(),
            Correlation = new CorrelationId(Guid.NewGuid()),
            CausationId = Guid.NewGuid(),
            ExpectedRevision = 4,
            ResultRevision = 5,
            Duration = TimeSpan.FromMilliseconds(12.5),
            QueueTime = TimeSpan.FromMilliseconds(2),
            ResultCode = SignalResultCode.Succeeded,
            ReasonCode = ReasonCodes.Get("state.invalid_transition"),
            NativeAbiVersion = new NativeAbiVersion(1, 2),
            NativeAbiBuildId = Context().BuildId,
            ReconnectCount = 1,
            SequenceGapCount = 2,
        };
        var sink = new CapturingSink();
        using var emitter = new SignalEmitter(sink);
        Activity? stopped = null;
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == SignalEmitter.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                if (activity.OperationName == "storage.commit")
                {
                    stopped = activity;
                }
            },
        };
        ActivitySource.AddActivityListener(listener);

        using (ObservabilityScope.Push(context))
        {
            var signal = emitter.Emit(SignalEventName.StorageCommitted, SignalLevel.Information);

            Assert.Same(signal, sink.Signal);
            Assert.Equal("storage.commit", signal.Name);
        }

        Assert.NotNull(stopped);
        var expected = new[]
        {
            "application.id", "instance.id", "build.id", "deployment.environment", "actor.ref", "workspace.id",
            "transport", "service.name", "interface.name", "method.name", "capability.name", "resource.ref",
            "command.id", "task.id", "run.id", "attempt.id", "correlation.id", "causation.id",
            "expected.revision", "result.revision", "duration.ms", "queue.time.ms", "result.code", "reason.code",
            "native.abi.version", "native.abi.build", "reconnect.count", "sequence.gap.count",
        };
        foreach (var key in expected)
        {
            Assert.Contains(key, sink.Signal!.Properties.Keys);
            Assert.Contains(stopped!.TagObjects, tag => tag.Key == key);
        }

        Assert.Equal(context.InstanceId.Value.ToString("N"), sink.Signal!.Properties["instance.id"]);
        Assert.Equal(12.5, (double)sink.Signal.Properties["duration.ms"]!);
        Assert.Equal(ActivityStatusCode.Unset, stopped!.Status);
    }

    [Fact]
    public void MissingOptionalDimensionsStayOmittedAndCoreIdentityIsAlwaysPresent()
    {
        var sink = new CapturingSink();
        using var emitter = new SignalEmitter(sink);
        var context = new ObservabilityContext(SignalApplicationDimension.Companion, new InstanceId(Guid.NewGuid()), SignalEnvironment.Development);

        using (ObservabilityScope.Push(context))
        {
            emitter.Emit(SignalEventName.ApplicationStarted, SignalLevel.Debug);
        }

        Assert.Equal(4, sink.Signal!.Properties.Count);
        Assert.Contains("application.id", sink.Signal.Properties.Keys);
        Assert.Contains("instance.id", sink.Signal.Properties.Keys);
        Assert.Contains("build.id", sink.Signal.Properties.Keys);
        Assert.Contains("deployment.environment", sink.Signal.Properties.Keys);
        Assert.DoesNotContain("actor.ref", sink.Signal.Properties.Keys);
        Assert.DoesNotContain("resource.ref", sink.Signal.Properties.Keys);
        Assert.DoesNotContain("duration.ms", sink.Signal.Properties.Keys);
    }

    [Fact]
    public void ContextRequiresRealBuildAndInstanceIdentityAndEmitterRequiresAmbientContext()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ObservabilityContext((SignalApplicationDimension)int.MaxValue,
            new InstanceId(Guid.NewGuid()), SignalEnvironment.Test));
        Assert.Throws<ArgumentException>(() => new ObservabilityContext(SignalApplicationDimension.ArcScope, default, SignalEnvironment.Test));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ObservabilityContext(SignalApplicationDimension.ArcScope,
            new InstanceId(Guid.NewGuid()), (SignalEnvironment)999));
        Assert.Throws<InvalidOperationException>(() => new SignalEmitter(new CapturingSink()).Emit(SignalEventName.OperationFailed, SignalLevel.Error));
    }

    [Fact]
    public void ApplicationBuildIdentityComesFromThePolicyStampedAssembly()
    {
        var assembly = typeof(SignalEmitterTests).Assembly;
        var expected = assembly.GetCustomAttributes<System.Reflection.AssemblyMetadataAttribute>()
            .Single(attribute => attribute.Key == "ArcForges.BuildId").Value;

        var context = ObservabilityContext.FromApplicationAssembly(SignalApplicationDimension.ArcScope,
            new InstanceId(Guid.NewGuid()), SignalEnvironment.Test, assembly);

        Assert.Equal(expected, context.BuildId);
    }

    [Fact]
    public void AmbientContextsFollowAsyncFlowAndRestoreNestedValues()
    {
        var outer = Context();
        var inner = outer with { Task = TaskId.New() };
        using (ObservabilityScope.Push(outer))
        {
            Assert.Same(outer, ObservabilityScope.Current);
            using (ObservabilityScope.Push(inner))
            {
                Assert.Same(inner, ObservabilityScope.Current);
            }

            Assert.Same(outer, ObservabilityScope.Current);
        }

        Assert.Null(ObservabilityScope.Current);
    }

    [Fact]
    public void MetricsUseOnlyBoundedServicePointLabelsAndCarryIdentityInScope()
    {
        var context = Context() with { Duration = TimeSpan.FromMilliseconds(8), ActorReference = "sha256:" + new string('c', 64), Task = TaskId.New() };
        var expectedInstance = context.InstanceId.Value.ToString("N", System.Globalization.CultureInfo.InvariantCulture);
        var observation = ObserveMetrics(context);

        Assert.Equal(1, observation.Count);
        Assert.Equal(8, observation.Duration);
        Assert.Equal(new KeyValuePair<string, object?>("service.name", nameof(SignalService.Storage)),
            Assert.Single(observation.CountTags));
        Assert.Equal(new KeyValuePair<string, object?>("service.name", nameof(SignalService.Storage)),
            Assert.Single(observation.DurationTags));
        Assert.DoesNotContain("instance.id", observation.CountTags.Keys);
        Assert.DoesNotContain("build.id", observation.CountTags.Keys);
        Assert.DoesNotContain("actor.ref", observation.CountTags.Keys);
        Assert.DoesNotContain("task.id", observation.CountTags.Keys);
        Assert.Equal(context.ApplicationId, observation.ScopeTags["application.id"]);
        Assert.Equal(expectedInstance, observation.ScopeTags["instance.id"]);
        Assert.Equal(context.BuildId, observation.ScopeTags["build.id"]);
        Assert.Equal(context.Environment.ToString(), observation.ScopeTags["deployment.environment"]);
        Assert.Equal(4, observation.ScopeTags.Count);

        using var emitter = new SignalEmitter(new CapturingSink());
        using (ObservabilityScope.Push(context))
        {
            emitter.Emit(SignalEventName.OperationCompleted, SignalLevel.Information);
        }
        var differentInstance = new ObservabilityContext(context.Application, new InstanceId(Guid.NewGuid()),
            context.Environment)
        {
            Service = context.Service
        };
        using (ObservabilityScope.Push(differentInstance))
        {
            Assert.Throws<InvalidOperationException>(() => emitter.Emit(SignalEventName.OperationCompleted, SignalLevel.Information));
        }

        var differentApplication = new ObservabilityContext(SignalApplicationDimension.Companion,
            context.InstanceId, context.Environment);
        using (ObservabilityScope.Push(differentApplication))
        {
            Assert.Throws<InvalidOperationException>(() => emitter.Emit(SignalEventName.OperationCompleted, SignalLevel.Information));
        }

        var differentEnvironment = new ObservabilityContext(context.Application, context.InstanceId,
            SignalEnvironment.Production);
        using (ObservabilityScope.Push(differentEnvironment))
        {
            Assert.Throws<InvalidOperationException>(() => emitter.Emit(SignalEventName.OperationCompleted, SignalLevel.Information));
        }
    }

    [Fact]
    public void MetricsUseNoPointLabelsAndCarryIdentityInScope()
    {
        var context = Context() with { Service = null, Duration = TimeSpan.FromMilliseconds(8) };
        var expectedInstance = context.InstanceId.Value.ToString("N", System.Globalization.CultureInfo.InvariantCulture);

        var observation = ObserveMetrics(context);

        Assert.Equal(1, observation.Count);
        Assert.Equal(8, observation.Duration);
        Assert.Empty(observation.CountTags);
        Assert.Empty(observation.DurationTags);
        Assert.Equal(context.ApplicationId, observation.ScopeTags["application.id"]);
        Assert.Equal(expectedInstance, observation.ScopeTags["instance.id"]);
        Assert.Equal(context.BuildId, observation.ScopeTags["build.id"]);
        Assert.Equal(context.Environment.ToString(), observation.ScopeTags["deployment.environment"]);
        Assert.Equal(4, observation.ScopeTags.Count);
    }

    [Fact]
    public void SignalEmitterHasNoCallerPropertyBagAndRejectsMarkerContent()
    {
        using var scope = ObservabilityScope.Push(Context());
        using var emitter = new SignalEmitter(new CapturingSink());
        var emitMethod = Assert.Single(typeof(SignalEmitter).GetMethods(), method => method.Name == nameof(SignalEmitter.Emit));
        Assert.Equal([typeof(SignalEventName), typeof(SignalLevel)],
            emitMethod.GetParameters().Select(parameter => parameter.ParameterType));

        const string pathCanary = "C:private.txt";
        const string apiKeyCanary = "ghp_0123456789abcdefghijklmnopqrstuvwxyzABCDE";
        const string jwtCanary = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
        Assert.Equal(typeof(SignalApplicationDimension), typeof(ObservabilityContext)
            .GetProperty(nameof(ObservabilityContext.Application))!.PropertyType);
        Assert.Throws<ArgumentException>(() => Validate(Context() with { NativeAbiBuildId = pathCanary }));
        Assert.Throws<ArgumentException>(() => Validate(Context() with { NativeAbiBuildId = apiKeyCanary }));
        Assert.Throws<ArgumentException>(() => Validate(Context() with { NativeAbiBuildId = jwtCanary }));
        Assert.Equal(typeof(SignalService), Nullable.GetUnderlyingType(
            typeof(ObservabilityContext).GetProperty(nameof(ObservabilityContext.Service))!.PropertyType));
        Assert.Throws<ArgumentOutOfRangeException>(() => Validate(Context() with { Service = (SignalService)int.MaxValue }));
        Assert.Throws<ArgumentException>(() => Validate(Context() with { NativeAbiBuildId = pathCanary }));

        const string marker = "[[SECRET-CANARY]] prompt=/home/user/private.txt access_token=never-log-this";
        Assert.Throws<ArgumentException>(() => ObservabilityScope.Push(Context() with { ActorReference = marker }));
        Assert.Throws<ArgumentException>(() => ObservabilityScope.Push(Context() with { RedactedResourceReference = marker }));

        var emitted = emitter.Emit(SignalEventName.SecretUsed, SignalLevel.Information);
        Assert.DoesNotContain("SECRET-CANARY", string.Join("|", emitted.Properties.Values), StringComparison.Ordinal);
    }

    [Fact]
    public void InvalidPresentDimensionsAreRejectedRatherThanSilentlyDropped()
    {
        Assert.Throws<ArgumentException>(() => Validate(Context() with { ActorReference = " " }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Validate(Context() with { Duration = TimeSpan.FromMilliseconds(-1) }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Validate(Context() with { SequenceGapCount = -1 }));
        Assert.Throws<ArgumentException>(() => Validate(Context() with { Correlation = new CorrelationId(Guid.Empty) }));
        Assert.Throws<ArgumentException>(() => Validate(Context() with { NativeAbiBuildId = "build prompt has secret" }));
    }

    [Fact]
    public void LivenessProbeDoesNotClaimReadinessOrCapabilityHealth()
    {
        HealthProbeResult liveness = HealthProbe.CheckLiveness();
        Assert.Equal(HealthProbeKind.Liveness, liveness.Kind);
        Assert.Equal(HealthProbeStatus.Healthy, liveness.Status);
        Assert.Empty(liveness.NotReadyDependencies);
        Assert.Empty(liveness.DimensionStatuses);
    }

    [Fact]
    public void ReadinessFailsClosedForEveryMissingRequiredDependency()
    {
        string[] required = ["capabilities", "storage"];
        HealthProbeResult missing = HealthProbe.CheckReadiness(required,
        [
            new RequiredDependencyObservation("storage", DependencyReadinessStatus.Available),
        ]);
        Assert.Equal(HealthProbeKind.Readiness, missing.Kind);
        Assert.Equal(HealthProbeStatus.Unavailable, missing.Status);
        Assert.Equal(new[] { "capabilities" }, missing.NotReadyDependencies);

        HealthProbeResult unavailable = HealthProbe.CheckReadiness(required,
        [
            new RequiredDependencyObservation("capabilities", DependencyReadinessStatus.Available),
            new RequiredDependencyObservation("storage", DependencyReadinessStatus.Unavailable),
        ]);
        Assert.Equal(HealthProbeStatus.Unavailable, unavailable.Status);
        Assert.Equal(new[] { "storage" }, unavailable.NotReadyDependencies);

        HealthProbeResult unknown = HealthProbe.CheckReadiness(required,
        [
            new RequiredDependencyObservation("capabilities", DependencyReadinessStatus.Available),
            new RequiredDependencyObservation("storage", DependencyReadinessStatus.Unknown),
        ]);
        Assert.Equal(HealthProbeStatus.Unavailable, unknown.Status);
        Assert.Equal(new[] { "storage" }, unknown.NotReadyDependencies);

        HealthProbeResult available = HealthProbe.CheckReadiness(required,
        [
            new RequiredDependencyObservation("storage", DependencyReadinessStatus.Available),
            new RequiredDependencyObservation("capabilities", DependencyReadinessStatus.Available),
        ]);
        Assert.Equal(HealthProbeStatus.Healthy, available.Status);
        Assert.Empty(available.NotReadyDependencies);
    }

    [Fact]
    public void ReadinessRejectsDuplicateAndUnownedDependencyObservations()
    {
        string[] required = ["storage"];
        Assert.Throws<ArgumentException>(() => HealthProbe.CheckReadiness(required,
        [
            new RequiredDependencyObservation("storage", DependencyReadinessStatus.Available),
            new RequiredDependencyObservation("storage", DependencyReadinessStatus.Available),
        ]));

        Assert.Throws<ArgumentException>(() => HealthProbe.CheckReadiness(required,
        [
            new RequiredDependencyObservation("unowned", DependencyReadinessStatus.Available),
        ]));
    }

    [Fact]
    public void CapabilityHealthUsesAllFiveSharedDimensionsAndReflectsSimulatedDegradation()
    {
        HealthDimension[] expectedDimensions =
        [
            HealthDimension.Reachable,
            HealthDimension.Ready,
            HealthDimension.Healthy,
            HealthDimension.Degraded,
            HealthDimension.Capacity,
        ];
        HealthDimensionObservation[] observations = expectedDimensions
            .Select(dimension => new HealthDimensionObservation(dimension,
                dimension == HealthDimension.Capacity ? HealthProbeStatus.Degraded : HealthProbeStatus.Healthy))
            .ToArray();

        HealthProbeResult degraded = HealthProbe.EvaluateCapabilityHealth(observations);
        Assert.Equal(HealthProbeKind.CapabilityHealth, degraded.Kind);
        Assert.Equal(HealthProbeStatus.Degraded, degraded.Status);
        Assert.Equal(expectedDimensions, degraded.DimensionStatuses.Keys);
        Assert.Equal(HealthProbeStatus.Degraded, degraded.DimensionStatuses[HealthDimension.Capacity]);

        HealthProbeResult unavailable = HealthProbe.EvaluateCapabilityHealth(expectedDimensions
            .Select(dimension => new HealthDimensionObservation(dimension,
                dimension == HealthDimension.Reachable ? HealthProbeStatus.Unavailable : HealthProbeStatus.Healthy)));
        Assert.Equal(HealthProbeStatus.Unavailable, unavailable.Status);
        Assert.Equal(HealthProbeStatus.Unavailable, unavailable.DimensionStatuses[HealthDimension.Reachable]);

        HealthProbeResult incomplete = HealthProbe.EvaluateCapabilityHealth(
            observations.Where(observation => observation.Dimension != HealthDimension.Ready));
        Assert.Equal(HealthProbeStatus.Unknown, incomplete.Status);
        Assert.Equal(HealthProbeStatus.Unknown, incomplete.DimensionStatuses[HealthDimension.Ready]);

        Assert.Throws<ArgumentException>(() => HealthProbe.EvaluateCapabilityHealth(
        [
            new HealthDimensionObservation(HealthDimension.Reachable, HealthProbeStatus.Healthy),
            new HealthDimensionObservation(HealthDimension.Reachable, HealthProbeStatus.Degraded),
        ]));

        Assert.Throws<ArgumentOutOfRangeException>(() => HealthProbe.EvaluateCapabilityHealth(
        [
            new HealthDimensionObservation((HealthDimension)int.MaxValue, HealthProbeStatus.Healthy),
        ]));
    }

    private static ObservabilityContext Context() => new(SignalApplicationDimension.ArcScope,
        new InstanceId(Guid.NewGuid()), SignalEnvironment.Test)
    {
        Service = SignalService.Storage,
    };

    private static MetricObservation ObserveMetrics(ObservabilityContext context)
    {
        var expectedInstance = context.InstanceId.Value.ToString("N", System.Globalization.CultureInfo.InvariantCulture);
        var countTags = new Dictionary<string, object?>(StringComparer.Ordinal);
        var durationTags = new Dictionary<string, object?>(StringComparer.Ordinal);
        var scopeTags = new Dictionary<string, object?>(StringComparer.Ordinal);
        var count = 0L;
        var duration = 0d;
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == SignalEmitter.MeterName
                    && instrument.Meter.Tags?.Any(tag => tag.Key == "instance.id" && Equals(tag.Value, expectedInstance)) == true)
                {
                    foreach (var tag in instrument.Meter.Tags!) scopeTags[tag.Key] = tag.Value;
                    meterListener.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
        {
            if (instrument.Name == "arcf_signal_count")
            {
                count = measurement;
                CopyTags(tags, countTags);
            }
        });
        listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, _) =>
        {
            if (instrument.Name == "arcf_signal_duration")
            {
                duration = measurement;
                CopyTags(tags, durationTags);
            }
        });
        listener.Start();
        using (var emitter = new SignalEmitter(new CapturingSink()))
        using (ObservabilityScope.Push(context))
        {
            emitter.Emit(SignalEventName.OperationCompleted, SignalLevel.Information);
        }

        return new MetricObservation(count, duration, countTags, durationTags, scopeTags);
    }

    private static void CopyTags(ReadOnlySpan<KeyValuePair<string, object?>> tags,
        Dictionary<string, object?> destination)
    {
        foreach (var tag in tags) destination.Add(tag.Key, tag.Value);
    }

    private sealed record MetricObservation(long Count, double Duration,
        Dictionary<string, object?> CountTags, Dictionary<string, object?> DurationTags,
        Dictionary<string, object?> ScopeTags);

    private static void Validate(ObservabilityContext context)
    {
        using var scope = ObservabilityScope.Push(context);
    }

    private sealed class CapturingSink : IStructuredEventSink
    {
        public StructuredSignal? Signal { get; private set; }

        public void Write(StructuredSignal signal) => Signal = signal;
    }
}
