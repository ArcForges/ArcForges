// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Text.Json;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Errors;
using Xunit;

namespace ArcForges.Observability.Tests;

public sealed class ExceptionReasonTests
{
    private const string Leak = "marker: C:\\Users\\someone\\diary.txt prompt=tell-me access_token=marker";

    [Fact]
    public void ExceptionsMapToRegisteredReasonCodesByTypeAndNeverByMessage()
    {
        (Exception Exception, string Code)[] cases =
        [
            (new TimeoutException(Leak), "dependency.timeout"),
            (new UnauthorizedAccessException(Leak), "perm.resource_denied"),
            (new FileNotFoundException(Leak, Leak), "state.not_found"),
            (new DirectoryNotFoundException(Leak), "state.not_found"),
            (new KeyNotFoundException(Leak), "state.not_found"),
            (new IOException(Leak), "resource.unavailable"),
            (new ArgumentNullException(Leak), "validation.invalid_request"),
            (new ArgumentOutOfRangeException(Leak, Leak), "validation.invalid_request"),
            (new FormatException(Leak), "validation.invalid_request"),
            (new JsonException(Leak), "validation.invalid_request"),
            (new InvalidOperationException(Leak), "state.invalid_transition"),
            (new ObjectDisposedException(Leak), "state.invalid_transition"),
            (new NotSupportedException(Leak), "internal.unexpected"),
            (new MarkerException(Leak), "internal.unexpected"),
        ];

        foreach ((Exception exception, string code) in cases)
        {
            ReasonCode? reason = ExceptionReasonMapper.Default.Map(exception);

            Assert.NotNull(reason);
            Assert.Equal(code, reason.Code);
            Assert.DoesNotContain("marker", reason.Code + reason.MessageKey, StringComparison.Ordinal);
            Assert.Same(ReasonCodes.Get(code), reason);
        }
    }

    [Fact]
    public void CancellationIsAnOutcomeNotAFailureAndWrappersReportTheirSingleInnerException()
    {
        Assert.Null(ExceptionReasonMapper.Default.Map(new OperationCanceledException(Leak)));
        Assert.Null(ExceptionReasonMapper.Default.Map(new TaskCanceledException(Leak)));
        Assert.Null(ExceptionReasonMapper.Default.Map(new AggregateException(new OperationCanceledException(Leak))));
        Assert.Equal("dependency.timeout", ExceptionReasonMapper.Default.Map(new AggregateException(new TimeoutException(Leak)))!.Code);
        Assert.Equal("dependency.timeout", ExceptionReasonMapper.Default.Map(
            new AggregateException(new AggregateException(new TimeoutException(Leak))))!.Code);
        Assert.Equal("perm.resource_denied", ExceptionReasonMapper.Default.Map(
            new TargetInvocationException(Leak, new UnauthorizedAccessException(Leak)))!.Code);
        Assert.Equal("internal.unexpected", ExceptionReasonMapper.Default.Map(
            new AggregateException(new TimeoutException(Leak), new IOException(Leak)))!.Code);
        Assert.Equal("internal.unexpected", ExceptionReasonMapper.Default.Map(new TargetInvocationException(Leak, null))!.Code);

        Exception deep = new TimeoutException(Leak);
        for (int index = 0; index < 20; index++)
        {
            deep = new TargetInvocationException(Leak, deep);
        }

        Assert.Equal("internal.unexpected", ExceptionReasonMapper.Default.Map(deep)!.Code);
        Assert.Throws<ArgumentNullException>(() => ExceptionReasonMapper.Default.Map(null!));
    }

    [Fact]
    public void OwnerRulesComeFirstAndMustNameAnExceptionTypeAndARegisteredReason()
    {
        ReasonCode denied = ReasonCodes.Get("perm.capability_denied");
        var mapper = new ExceptionReasonMapper(
        [
            new KeyValuePair<Type, ReasonCode>(typeof(MarkerException), denied),
            new KeyValuePair<Type, ReasonCode>(typeof(InvalidOperationException), ReasonCodes.Get("state.gone")),
        ]);

        Assert.Same(denied, mapper.Map(new MarkerException(Leak)));
        Assert.Equal("state.gone", mapper.Map(new InvalidOperationException(Leak))!.Code);
        Assert.Equal("state.gone", mapper.Map(new ObjectDisposedException(Leak))!.Code);
        Assert.Equal("dependency.timeout", mapper.Map(new TimeoutException(Leak))!.Code);
        Assert.Equal("internal.unexpected", new ExceptionReasonMapper([]).Map(new MarkerException(Leak))!.Code);
        Assert.Throws<ArgumentException>(() => new ExceptionReasonMapper(
            [new KeyValuePair<Type, ReasonCode>(typeof(string), denied)]));
        Assert.Throws<ArgumentNullException>(() => new ExceptionReasonMapper(
            [new KeyValuePair<Type, ReasonCode>(typeof(MarkerException), null!)]));
    }

    [Fact]
    public void AFailureReachesTheExporterAsAReasonCodeOnly()
    {
        var instance = new InstanceId(Guid.NewGuid());
        using var exporter = new LocalTestExporter(instance);
        using var emitter = new SignalEmitter(exporter);
        var context = new ObservabilityContext(SignalApplicationDimension.ArcScope, instance, SignalEnvironment.Test);

        foreach (Exception exception in new Exception[]
        {
            new IOException(Leak),
            new UnauthorizedAccessException(Leak),
            new InvalidOperationException(Leak, new TimeoutException(Leak)),
            new MarkerException(Leak),
        })
        {
            using (ObservabilityScope.Push(context.WithFailure(exception)))
            {
                emitter.Emit(SignalEventName.OperationFailed, SignalLevel.Error);
            }
        }

        Assert.Equal(["resource.unavailable", "perm.resource_denied", "state.invalid_transition", "internal.unexpected"],
            exporter.Signals.Select(signal => (string)signal.Properties["reason.code"]!));
        Assert.All(exporter.Signals, signal => Assert.Equal("Failed", signal.Properties["result.code"]));
        Assert.DoesNotContain("marker", exporter.ExportedText(), StringComparison.Ordinal);
        Assert.DoesNotContain("diary", exporter.ExportedText(), StringComparison.Ordinal);
        Assert.DoesNotContain("exception", exporter.ExportedText(), StringComparison.OrdinalIgnoreCase);

        ObservabilityContext cancelled = context.WithFailure(new OperationCanceledException(Leak));
        Assert.Equal(SignalResultCode.Cancelled, cancelled.ResultCode);
        Assert.Null(cancelled.ReasonCode);
        Assert.Throws<ArgumentNullException>(() => context.WithFailure(null!));
        Assert.Equal("state.gone", context.WithFailure(new InvalidOperationException(Leak),
            new ExceptionReasonMapper([new KeyValuePair<Type, ReasonCode>(typeof(InvalidOperationException), ReasonCodes.Get("state.gone"))]))
            .ReasonCode!.Code);
    }

    [Fact]
    public void FailureRecordingNeverReadsTheExceptionMessageOrStack()
    {
        var exception = new ThrowingMessageException();

        ObservabilityContext context = new ObservabilityContext(SignalApplicationDimension.ArcScope,
            new InstanceId(Guid.NewGuid()), SignalEnvironment.Test).WithFailure(exception);

        Assert.Equal("internal.unexpected", context.ReasonCode!.Code);
        Assert.False(exception.MessageWasRead);
        Assert.False(exception.DataWasRead);
    }

    [SuppressMessage("Design", "CA1032:Implement standard exception constructors", Justification = "A test-only exception type that exists to carry a marker message.")]
    private sealed class MarkerException(string message) : Exception(message);

    [SuppressMessage("Design", "CA1032:Implement standard exception constructors", Justification = "A test-only exception type that records whether its members were read.")]
    private sealed class ThrowingMessageException : Exception
    {
        public bool MessageWasRead { get; private set; }

        public bool DataWasRead { get; private set; }

        public override string Message
        {
            get
            {
                MessageWasRead = true;
                return Leak;
            }
        }

        public override System.Collections.IDictionary Data
        {
            get
            {
                DataWasRead = true;
                return base.Data;
            }
        }

        public override string? StackTrace
        {
            get
            {
                MessageWasRead = true;
                return Leak;
            }
        }
    }
}
