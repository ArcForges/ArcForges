// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;

namespace ArcForges.Observability.Desktop;

internal static class OtlpJson
{
    internal static byte[] Span(ScrubbedSpan span, ObservabilityContext identity, int maximumBytes) => Encode(maximumBytes, writer =>
    {
        Begin(writer, "resourceSpans", "scopeSpans", "spans", identity);
        writer.WriteStartObject();
        writer.WriteString("traceId", span.TraceId);
        writer.WriteString("spanId", span.SpanId);
        if (span.ParentSpanId is not null) writer.WriteString("parentSpanId", span.ParentSpanId);
        writer.WriteString("name", span.Name);
        writer.WriteNumber("kind", (int)span.Kind + 1);
        writer.WriteString("startTimeUnixNano", Nano(new DateTimeOffset(span.StartTimeUtc, TimeSpan.Zero)));
        writer.WriteString("endTimeUnixNano", Nano(new DateTimeOffset(span.StartTimeUtc, TimeSpan.Zero) + span.Duration));
        Attributes(writer, RedactionProcessor.ScrubFields(span.Tags));
        writer.WriteStartArray("events");
        foreach (ScrubbedSpanEvent item in span.Events.Take(64))
        {
            writer.WriteStartObject();
            writer.WriteString("name", item.Name);
            writer.WriteString("timeUnixNano", Nano(item.Timestamp));
            Attributes(writer, RedactionProcessor.ScrubFields(item.Tags));
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
        if (span.Events.Count > 64) writer.WriteNumber("droppedEventsCount", span.Events.Count - 64);
        writer.WriteStartObject("status");
        writer.WriteNumber("code", (int)span.Status);
        writer.WriteEndObject();
        writer.WriteEndObject();
        End(writer);
    });

    internal static byte[] Log(StructuredSignal signal, ObservabilityContext identity, int maximumBytes) => Encode(maximumBytes, writer =>
    {
        Begin(writer, "resourceLogs", "scopeLogs", "logRecords", identity);
        writer.WriteStartObject();
        writer.WriteString("timeUnixNano", Nano(signal.OccurredAt));
        writer.WriteNumber("severityNumber", 1 + (int)signal.Level * 4);
        writer.WriteStartObject("body");
        writer.WriteString("stringValue", signal.Name);
        writer.WriteEndObject();
        Attributes(writer, RedactionProcessor.ScrubFields(signal.Properties));
        writer.WriteEndObject();
        End(writer);
    });

    internal static byte[] Metric(string name, MetricShape shape, double value,
        IReadOnlyDictionary<string, object?> labels, DateTimeOffset start, DateTimeOffset end,
        ObservabilityContext identity, int maximumBytes) => Encode(maximumBytes, writer =>
    {
        Begin(writer, "resourceMetrics", "scopeMetrics", "metrics", identity);
        writer.WriteStartObject();
        writer.WriteString("name", name);
        writer.WriteString("unit", name == "arcf_signal_duration" ? "ms" : name == "arcf_trace_buffer_bytes" ? "By" : "1");
        writer.WriteStartObject(shape == MetricShape.Histogram ? "histogram" : shape == MetricShape.Gauge ? "gauge" : "sum");
        if (shape != MetricShape.Gauge)
        {
            writer.WriteNumber("aggregationTemporality", shape == MetricShape.CumulativeSum ? 2 : 1);
            if (shape != MetricShape.Histogram) writer.WriteBoolean("isMonotonic", true);
        }
        writer.WriteStartArray("dataPoints");
        writer.WriteStartObject();
        writer.WriteString("timeUnixNano", Nano(end));
        if (shape != MetricShape.Gauge) writer.WriteString("startTimeUnixNano", Nano(start));
        Attributes(writer, labels);
        if (shape == MetricShape.Histogram)
        {
            writer.WriteString("count", "1");
            writer.WriteNumber("sum", value);
            writer.WriteNumber("min", value);
            writer.WriteNumber("max", value);
            // A delta histogram with no explicit bounds has a single (+infinity) bucket.
            writer.WriteStartArray("bucketCounts");
            writer.WriteStringValue("1");
            writer.WriteEndArray();
        }
        else writer.WriteNumber("asDouble", value);
        writer.WriteEndObject();
        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.WriteEndObject();
        End(writer);
    });

    private static byte[] Encode(int maximumBytes, Action<Utf8JsonWriter> write)
    {
        using var stream = new LimitedStream(maximumBytes);
        using (var writer = new Utf8JsonWriter(stream)) write(writer);
        return stream.ToArray();
    }

    private static void Begin(Utf8JsonWriter writer, string resource, string scope, string records, ObservabilityContext identity)
    {
        writer.WriteStartObject();
        writer.WriteStartArray(resource);
        writer.WriteStartObject();
        writer.WriteStartObject("resource");
        using var pushed = ObservabilityScope.Push(identity);
        // Only deployment identity belongs on the resource; request/actor identifiers remain point attributes.
        Attributes(writer, RedactionProcessor.ScrubFields(new Dictionary<string, object?>
        {
            ["application.id"] = identity.ApplicationId,
            ["instance.id"] = identity.InstanceId.Value.ToString("N", CultureInfo.InvariantCulture),
            ["build.id"] = identity.BuildId,
            ["deployment.environment"] = identity.Environment.ToString(),
        }));
        writer.WriteEndObject();
        writer.WriteStartArray(scope);
        writer.WriteStartObject();
        writer.WriteStartObject("scope");
        writer.WriteString("name", SignalEmitter.SourceName);
        writer.WriteEndObject();
        writer.WriteStartArray(records);
    }

    private static void End(Utf8JsonWriter writer)
    {
        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void Attributes(Utf8JsonWriter writer, IReadOnlyDictionary<string, object?> fields)
    {
        writer.WriteStartArray("attributes");
        foreach ((string name, object? value) in fields)
        {
            writer.WriteStartObject();
            writer.WriteString("key", name);
            writer.WriteStartObject("value");
            switch (value)
            {
                case string text: writer.WriteString("stringValue", text); break;
                case bool flag: writer.WriteBoolean("boolValue", flag); break;
                case int number: writer.WriteString("intValue", number.ToString(CultureInfo.InvariantCulture)); break;
                case long number: writer.WriteString("intValue", number.ToString(CultureInfo.InvariantCulture)); break;
                case sbyte number: writer.WriteString("intValue", number.ToString(CultureInfo.InvariantCulture)); break;
                case byte number: writer.WriteString("intValue", number.ToString(CultureInfo.InvariantCulture)); break;
                case short number: writer.WriteString("intValue", number.ToString(CultureInfo.InvariantCulture)); break;
                case ushort number: writer.WriteString("intValue", number.ToString(CultureInfo.InvariantCulture)); break;
                case uint number: writer.WriteString("intValue", number.ToString(CultureInfo.InvariantCulture)); break;
                // OTLP AnyValue has signed int64 only. Preserve the entire approved unsigned revision range losslessly.
                case ulong number: writer.WriteString("stringValue", number.ToString(CultureInfo.InvariantCulture)); break;
                case double number: writer.WriteNumber("doubleValue", number); break;
                default: throw new InvalidOperationException("The reviewed telemetry shape has an unsupported OTLP scalar.");
            }
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }

    private static string Nano(DateTimeOffset time) => checked((time.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) * 100)
        .ToString(CultureInfo.InvariantCulture);

    private sealed class LimitedStream(int limit) : MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count)
        {
            Check(count);
            base.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Check(buffer.Length);
            base.Write(buffer);
        }

        private void Check(int count)
        {
            if (Length + count > limit) throw new InvalidDataException("The sanitized record exceeds its byte budget.");
        }
    }
}

internal enum MetricShape { DeltaSum, CumulativeSum, Histogram, Gauge }
