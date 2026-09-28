// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Reflection;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using Xunit;

namespace ArcForges.Observability.Tests;

public sealed class SignalEmitterTests
{
    [Fact]
    public void OneEmissionCarriesEveryPresentDimensionToTraceAndStructuredEvent()
    {
        var context = new ObservabilityContext("arcscope", new InstanceId(Guid.NewGuid()), "local.0123456789abcdef", "test")
        {
            ActorReference = "sha256:" + new string('a', 64),
            Workspace = new WorkspaceId(Guid.NewGuid()),
            Transport = "local-rpc",
            Service = "storage",
            Interface = "IStore",
            Method = "Commit",
            Capability = "resource.write",
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
            ResultCode = "ok",
            ReasonCode = "store.committed",
            NativeAbiVersion = "1.2.0",
            NativeAbiBuildId = "native-build-4",
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
            ActivityStopped = activity => stopped = activity,
        };
        ActivitySource.AddActivityListener(listener);

        using (ObservabilityScope.Push(context))
        {
            var signal = emitter.Emit("store.commit", SignalLevel.Information);

            Assert.Same(signal, sink.Signal);
            Assert.Equal("store.commit", signal.Name);
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
        var context = new ObservabilityContext("companion", new InstanceId(Guid.NewGuid()), "build-17", "development");

        using (ObservabilityScope.Push(context))
        {
            emitter.Emit("startup.ready", SignalLevel.Debug);
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
        Assert.Throws<ArgumentException>(() => new ObservabilityContext(" ", new InstanceId(Guid.NewGuid()), "build", "test"));
        Assert.Throws<ArgumentException>(() => new ObservabilityContext("arcscope", default, "build", "test"));
        Assert.Throws<ArgumentException>(() => new ObservabilityContext("arcscope", new InstanceId(Guid.NewGuid()), "", "test"));
        Assert.Throws<InvalidOperationException>(() => new SignalEmitter(new CapturingSink()).Emit("event.test", SignalLevel.Error));
    }

    [Fact]
    public void ApplicationBuildIdentityComesFromThePolicyStampedAssembly()
    {
        var assembly = typeof(SignalEmitterTests).Assembly;
        var expected = assembly.GetCustomAttributes<System.Reflection.AssemblyMetadataAttribute>()
            .Single(attribute => attribute.Key == "ArcForges.BuildId").Value;

        var context = ObservabilityContext.FromApplicationAssembly("arcscope", new InstanceId(Guid.NewGuid()), "test", assembly);

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
    public void MetricsUseOnlyLowCardinalityIdentityAndRecordPresentDuration()
    {
        var context = Context() with { Duration = TimeSpan.FromMilliseconds(8), ActorReference = "sha256:" + new string('c', 64), Task = TaskId.New() };
        var expectedInstance = context.InstanceId.Value.ToString("N", System.Globalization.CultureInfo.InvariantCulture);
        var countTags = new HashSet<string>(StringComparer.Ordinal);
        var durationTags = new HashSet<string>(StringComparer.Ordinal);
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
                CopyTagNames(tags, countTags);
            }
        });
        listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, _) =>
        {
            if (instrument.Name == "arcf_signal_duration")
            {
                duration = measurement;
                CopyTagNames(tags, durationTags);
            }
        });
        listener.Start();
        using var emitter = new SignalEmitter(new CapturingSink());
        using (ObservabilityScope.Push(context))
        {
            emitter.Emit("execution.completed", SignalLevel.Information);
        }

        Assert.Equal(1, count);
        Assert.Equal(8, duration);
        Assert.True(countTags.SetEquals(["service.name"]));
        Assert.DoesNotContain("instance.id", countTags);
        Assert.DoesNotContain("build.id", countTags);
        Assert.DoesNotContain("actor.ref", countTags);
        Assert.DoesNotContain("task.id", countTags);
        Assert.True(countTags.SetEquals(durationTags));
        Assert.Equal(context.ApplicationId, scopeTags["application.id"]);
        Assert.Equal(expectedInstance, scopeTags["instance.id"]);
        Assert.Equal(context.BuildId, scopeTags["build.id"]);
        Assert.Equal(context.Environment, scopeTags["deployment.environment"]);

        var differentInstance = new ObservabilityContext(context.ApplicationId, new InstanceId(Guid.NewGuid()),
            context.BuildId, context.Environment)
        {
            Service = context.Service
        };
        using (ObservabilityScope.Push(differentInstance))
        {
            Assert.Throws<InvalidOperationException>(() => emitter.Emit("execution.completed", SignalLevel.Information));
        }
    }

    [Fact]
    public void SignalEmitterHasNoCallerPropertyBagAndRejectsMarkerContent()
    {
        using var scope = ObservabilityScope.Push(Context());
        using var emitter = new SignalEmitter(new CapturingSink());
        Assert.Equal(2, typeof(SignalEmitter).GetMethod(nameof(SignalEmitter.Emit))!.GetParameters().Length);
        Assert.Throws<ArgumentException>(() => emitter.Emit("Secret Used", SignalLevel.Information));

        const string marker = "[[SECRET-CANARY]] prompt=/home/user/private.txt access_token=never-log-this";
        Assert.Throws<ArgumentException>(() => ObservabilityScope.Push(Context() with { Method = marker }));
        Assert.Throws<ArgumentException>(() => ObservabilityScope.Push(Context() with { ActorReference = marker }));
        Assert.Throws<ArgumentException>(() => ObservabilityScope.Push(Context() with { RedactedResourceReference = marker }));

        var emitted = emitter.Emit("secret.used", SignalLevel.Information);
        Assert.DoesNotContain("SECRET-CANARY", string.Join("|", emitted.Properties.Values), StringComparison.Ordinal);
    }

    [Fact]
    public void InvalidPresentDimensionsAreRejectedRatherThanSilentlyDropped()
    {
        Assert.Throws<ArgumentException>(() => Validate(Context() with { ActorReference = " " }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Validate(Context() with { Duration = TimeSpan.FromMilliseconds(-1) }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Validate(Context() with { SequenceGapCount = -1 }));
        Assert.Throws<ArgumentException>(() => Validate(Context() with { Correlation = new CorrelationId(Guid.Empty) }));
        Assert.Throws<ArgumentException>(() => new ObservabilityContext("/var/tmp/token=marker", new InstanceId(Guid.NewGuid()), "build-17", "test"));
        Assert.Throws<ArgumentException>(() => new ObservabilityContext("arcscope", new InstanceId(Guid.NewGuid()), "build prompt has secret", "test"));
    }

    private static ObservabilityContext Context() => new("arcscope", new InstanceId(Guid.NewGuid()), "build-17", "test")
    {
        Service = "test-service",
    };

    private static void CopyTagNames(ReadOnlySpan<KeyValuePair<string, object?>> tags, HashSet<string> destination)
    {
        foreach (var tag in tags)
        {
            destination.Add(tag.Key);
        }
    }

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
