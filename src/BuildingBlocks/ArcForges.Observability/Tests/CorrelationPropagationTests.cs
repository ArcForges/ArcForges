// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Diagnostics;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;
using Google.Protobuf;
using Xunit;

namespace ArcForges.Observability.Tests;

public sealed class CorrelationPropagationTests
{
    [Fact]
    public async Task OriginAndAvailableLocalHopsShareOneTraceAndResolveTaskAndRun()
    {
        var stopped = new ConcurrentQueue<StoppedActivity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == SignalEmitter.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                if (activity.OperationName.StartsWith("observability.", StringComparison.Ordinal))
                {
                    stopped.Enqueue(new StoppedActivity(
                        activity.OperationName, activity.TraceId, activity.SpanId, activity.ParentSpanId));
                }
            },
        };
        ActivitySource.AddActivityListener(listener);

        var index = new TaskTraceIndex();
        var propagation = new CorrelationPropagation(index);
        TaskId task = TaskId.New();
        RunId run = RunId.New();
        using (CorrelationPropagationScope origin = propagation.BeginOrigin(Context() with { Task = task, Run = run }))
        {
            CorrelationTraceContext current = origin.Context;
            Assert.NotEqual(default, current.ActivityContext.TraceId);
            Assert.Equal(current.Correlation, ObservabilityScope.Current!.Correlation);

            foreach (ObservabilityHopKind hop in Enum.GetValues<ObservabilityHopKind>())
            {
                CorrelationPropagationScope child = propagation.BeginLocalHop(current, Context() with { Task = task, Run = run }, hop);
                Assert.Equal(current.Correlation, child.Context.Correlation);
                Assert.Equal(current.ActivityContext.TraceId, child.Context.ActivityContext.TraceId);
                Assert.Equal(child.Context.Correlation, ObservabilityScope.Current!.Correlation);
                current = child.Context;

                await Task.Yield();
                child.Dispose();
            }

            Assert.Equal(origin.Context.ActivityContext.TraceId, current.ActivityContext.TraceId);
            Assert.NotEqual(origin.Context.Correlation.Value.ToString("N"), current.ActivityContext.TraceId.ToHexString());
        }

        Assert.True(index.TryResolve(task, out ActivityTraceId taskTrace));
        Assert.True(index.TryResolve(run, out ActivityTraceId runTrace));
        Assert.Equal(taskTrace, runTrace);
        Assert.Equal(taskTrace, stopped.First(item => item.Name == "observability.origin").TraceId);

        StoppedActivity[] chain = stopped.OrderBy(item => item.Name, StringComparer.Ordinal).ToArray();
        StoppedActivity root = Assert.Single(chain, item => item.Name == "observability.origin");
        Assert.Equal(Enum.GetValues<ObservabilityHopKind>().Length, chain.Length - 1);
        ActivitySpanId previous = root.SpanId;
        foreach (ObservabilityHopKind hop in Enum.GetValues<ObservabilityHopKind>())
        {
            string name = hop switch
            {
                ObservabilityHopKind.Http => "observability.http",
                ObservabilityHopKind.Queue => "observability.queue",
                ObservabilityHopKind.Worker => "observability.worker",
                ObservabilityHopKind.Realtime => "observability.realtime",
                ObservabilityHopKind.Provider => "observability.provider",
                _ => throw new ArgumentOutOfRangeException(nameof(hop)),
            };
            StoppedActivity operation = Assert.Single(chain, item => item.Name == name);
            Assert.Equal(root.TraceId, operation.TraceId);
            Assert.Equal(previous, operation.ParentSpanId);
            previous = operation.SpanId;
        }
    }

    [Fact]
    public void OriginAcceptsOnlyValidatedTypedWireCorrelation()
    {
        var propagation = new CorrelationPropagation(new TaskTraceIndex());
        CorrelationId expected = new(Guid.NewGuid());
        Id validWireValue = expected.ToWire();

        using (CorrelationPropagationScope origin = propagation.BeginOrigin(Context(), validWireValue))
        {
            Assert.Equal(expected, origin.Context.Correlation);
        }

        Id malformed = new() { Value = ByteString.CopyFrom(new byte[15]) };
        Assert.Throws<ArgumentException>(() => propagation.BeginOrigin(Context(), malformed));
    }

    [Fact]
    public void LocalHopCannotReplaceItsParentCorrelation()
    {
        var propagation = new CorrelationPropagation(new TaskTraceIndex());
        using CorrelationPropagationScope origin = propagation.BeginOrigin(Context());
        ObservabilityContext foreign = Context() with { Correlation = new CorrelationId(Guid.NewGuid()) };

        Assert.Throws<ArgumentException>(() => propagation.BeginLocalHop(origin.Context, foreign, ObservabilityHopKind.Worker));
    }

    [Fact]
    public void TaskTraceIndexIsBoundedTypedIdempotentAndConflictSafe()
    {
        var index = new TaskTraceIndex(capacity: 2);
        Assert.Equal(2, index.Capacity);
        TaskId firstTask = TaskId.New();
        RunId firstRun = RunId.New();
        ActivityTraceId firstTrace = ActivityTraceId.CreateRandom();
        ActivityTraceId conflictingTrace = ActivityTraceId.CreateRandom();

        Assert.True(index.TryRecord(firstTask, firstRun, firstTrace));
        Assert.True(index.TryRecord(firstTask, firstRun, firstTrace));
        TaskId conflictingTask = TaskId.New();
        Assert.False(index.TryRecord(conflictingTask, firstRun, conflictingTrace));
        Assert.False(index.TryResolve(conflictingTask, out _));
        Assert.True(index.TryResolve(firstTask, out ActivityTraceId resolvedTask));
        Assert.True(index.TryResolve(firstRun, out ActivityTraceId resolvedRun));
        Assert.Equal(firstTrace, resolvedTask);
        Assert.Equal(firstTrace, resolvedRun);

        TaskId newestTask = TaskId.New();
        Assert.True(index.TryRecord(newestTask, null, conflictingTrace));
        Assert.False(index.TryResolve(firstTask, out _));
        Assert.True(index.TryResolve(firstRun, out resolvedRun));
        Assert.Equal(firstTrace, resolvedRun);
        Assert.True(index.TryResolve(newestTask, out resolvedTask));
        Assert.Equal(conflictingTrace, resolvedTask);
    }

    [Fact]
    public void TaskTraceIndexConcurrentWritesRemainResolvable()
    {
        const int entries = 64;
        var index = new TaskTraceIndex(capacity: entries);
        var values = new ConcurrentBag<(TaskId Task, ActivityTraceId Trace)>();

        Parallel.For(0, entries, _ =>
        {
            TaskId task = TaskId.New();
            ActivityTraceId trace = ActivityTraceId.CreateRandom();
            Assert.True(index.TryRecord(task, null, trace));
            values.Add((task, trace));
        });

        Assert.Equal(entries, values.Count);
        foreach ((TaskId task, ActivityTraceId trace) in values)
        {
            Assert.True(index.TryResolve(task, out ActivityTraceId resolved));
            Assert.Equal(trace, resolved);
        }
    }

    private static ObservabilityContext Context() => new(
        SignalApplicationDimension.ArcScope,
        new InstanceId(Guid.NewGuid()),
        SignalEnvironment.Test);

    private sealed record StoppedActivity(
        string Name,
        ActivityTraceId TraceId,
        ActivitySpanId SpanId,
        ActivitySpanId ParentSpanId);
}
