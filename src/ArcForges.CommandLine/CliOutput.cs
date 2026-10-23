// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Text;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.CommandLine;

/// <summary>
/// The CLI's output modes (experience/cli.md section 2; architecture 12 section 3):
/// <list type="bullet">
/// <item>Human: width-aware tables (<c>key: value</c> lines below 60 columns), colour only on a terminal without <c>NO_COLOR</c> or
/// <c>--no-color</c>, states always as words, relative times. Errors go to stderr as
/// <c>error: &lt;message&gt; (&lt;CATEGORY&gt;/&lt;code&gt;, correlation &lt;id&gt;)</c>.</item>
/// <item><c>--json</c>: stdout carries only JSON, one document per result in the canonical protobuf JSON mapping, with <c>*Id</c> fields
/// rendered as Crockford base32 text (contracts README section 8); streams are JSON Lines; errors are <c>{"error": &lt;ArcError&gt;}</c>
/// on stdout.</item>
/// <item><c>--quiet</c>: only essential output.</item>
/// </list>
/// </summary>
public sealed class CliOutput
{
    private static readonly JsonFormatter Formatter = new(JsonFormatter.Settings.Default.WithFormatDefaultValues(false));

    private readonly TextWriter _out;
    private readonly TextWriter _error;

    /// <summary>Creates the output.</summary>
    public CliOutput(TextWriter output, TextWriter error, bool json, bool quiet, bool color, bool verbose, int width)
    {
        _out = output;
        _error = error;
        Json = json;
        Quiet = quiet;
        Color = color;
        Verbose = verbose;
        Width = width;
    }

    /// <summary>Machine output.</summary>
    public bool Json { get; }

    /// <summary>Only essential output.</summary>
    public bool Quiet { get; }

    /// <summary>Colour is enabled.</summary>
    public bool Color { get; }

    /// <summary>Correlation IDs and timings are shown.</summary>
    public bool Verbose { get; }

    /// <summary>The terminal width (or 120 when not a terminal).</summary>
    public int Width { get; }

    /// <summary>Standard output.</summary>
    public TextWriter Out => _out;

    /// <summary>Standard error.</summary>
    public TextWriter Error => _error;

    /// <summary>Writes one JSON document for a protobuf message (indented).</summary>
    public void Document(IMessage message) => WriteJson(ToJsonNode(message), indented: true);

    /// <summary>Writes one JSON document built from named protobuf parts and plain values.</summary>
    public void Document(JsonObject document) => WriteJson(document, indented: true);

    /// <summary>Writes one JSON document through <paramref name="write"/> (documents written without protobuf reflection).</summary>
    public void Document(Action<Utf8JsonWriter> write)
    {
        ArgumentNullException.ThrowIfNull(write);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            write(writer);
        }

        _out.WriteLine(Encoding.UTF8.GetString(buffer.ToArray()));
    }

    /// <summary>Writes one JSON Lines record for a protobuf message.</summary>
    public void JsonLine(IMessage message) => WriteJson(ToJsonNode(message), indented: false);

    /// <summary>The canonical JSON of a message with <c>*Id</c> fields as base32 text.</summary>
    public static JsonNode ToJsonNode(IMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var node = JsonNode.Parse(Formatter.Format(message)) ?? new JsonObject();
        RenderIds(node);
        return node;
    }

    /// <summary>A human line (suppressed by <c>--quiet</c>).</summary>
    public void Line(string text = "")
    {
        if (!Quiet)
        {
            _out.WriteLine(text);
        }
    }

    /// <summary>An essential line (printed with <c>--quiet</c> as well).</summary>
    public void Essential(string text) => _out.WriteLine(text);

    /// <summary>A note on stderr (human mode only).</summary>
    public void Note(string text)
    {
        if (!Json && !Quiet)
        {
            _error.WriteLine("arcforges: " + text);
        }
    }

    /// <summary>A verbose note on stderr (<c>--verbose</c>).</summary>
    public void Trace(string text)
    {
        if (Verbose)
        {
            _error.WriteLine("arcforges: " + text);
        }
    }

    /// <summary>Aligned <c>key  value</c> lines, or <c>key: value</c> below 60 columns.</summary>
    public void KeyValues(IReadOnlyList<(string Key, string Value)> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        if (Quiet)
        {
            return;
        }

        var keyWidth = rows.Count == 0 ? 0 : rows.Max(row => row.Key.Length);
        foreach (var (key, value) in rows)
        {
            _out.WriteLine(Width < 60 ? key + ": " + value : key.PadRight(keyWidth + 2) + value);
        }
    }

    /// <summary>A width-aware table; below 60 columns each row becomes a block of <c>key: value</c> lines.</summary>
    public void Table(IReadOnlyList<string> headers, IReadOnlyList<IReadOnlyList<string>> rows)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(rows);
        if (Quiet)
        {
            return;
        }

        if (Width < 60)
        {
            foreach (var row in rows)
            {
                for (var column = 0; column < headers.Count; column++)
                {
                    _out.WriteLine(headers[column].ToLowerInvariant() + ": " + row[column]);
                }

                _out.WriteLine();
            }

            return;
        }

        var widths = headers.Select((header, column) => Math.Max(header.Length, rows.Count == 0 ? 0 : rows.Max(row => VisibleLength(row[column])))).ToArray();
        var total = widths.Sum() + (2 * (widths.Length - 1));
        if (total > Width && widths.Length > 0)
        {
            // The last column is truncated to fit the terminal.
            widths[^1] = Math.Max(8, widths[^1] - (total - Width));
        }

        _out.WriteLine(Row(headers, widths));
        foreach (var row in rows)
        {
            _out.WriteLine(Row(row, widths));
        }
    }

    /// <summary>A lifecycle state as a word, coloured on a terminal (never colour alone).</summary>
    public string State(NodeLifecycleState state)
    {
        var word = Word(state);
        var colour = state switch
        {
            NodeLifecycleState.Ready => "32",
            NodeLifecycleState.Degraded or NodeLifecycleState.Recovering or NodeLifecycleState.Starting => "33",
            NodeLifecycleState.Stopping or NodeLifecycleState.Updating => "31",
            _ => null,
        };
        return Color && colour is not null ? $"\u001b[{colour}m{word}\u001b[0m" : word;
    }

    /// <summary>The upper-case word of a lifecycle state.</summary>
    public static string Word(NodeLifecycleState state) => state switch
    {
        NodeLifecycleState.Starting => "STARTING",
        NodeLifecycleState.Recovering => "RECOVERING",
        NodeLifecycleState.Ready => "READY",
        NodeLifecycleState.Degraded => "DEGRADED",
        NodeLifecycleState.Stopping => "STOPPING",
        NodeLifecycleState.Updating => "UPDATING",
        _ => "UNKNOWN",
    };

    /// <summary>A relative time for human output.</summary>
    public static string When(Instant? instant) =>
        ProtoTime.ToDateTimeOffset(instant) is { } time ? Durations.Relative(time, DateTimeOffset.UtcNow) : "-";

    /// <summary>Prints a node error and returns its exit code.</summary>
    public int Fail(ArcError error, Id? correlation)
    {
        ArgumentNullException.ThrowIfNull(error);
        if (Json)
        {
            var document = new JsonObject { ["error"] = ToJsonNode(error) };
            Document(document);
        }
        else
        {
            var category = error.Category.ToString().ToUpperInvariant();
            var id = IdText.Format(correlation ?? error.CorrelationId);
            if (error.Code == "approval_required" && error.Details?.State?.Resource?.Id is { } approval)
            {
                // cli.md section 5: the approval is pending; exit 6.
                var text = IdText.Format(approval);
                _error.WriteLine($"Waiting for approval {text} (approve in ArcForges Desktop or with 'arcforges approvals approve {text}')");
                return ExitCodes.For(error);
            }

            _error.WriteLine($"error: {Messages.For(error)} ({category}/{error.Code}" + (id.Length > 0 ? $", correlation {id})" : ")"));
        }

        return ExitCodes.For(error);
    }

    /// <summary>Prints that no ready node could be reached and returns the exit code (75, or 5 when refused).</summary>
    public int Fail(NodeUnavailableException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var message = exception.Reason == NodeUnavailableReason.AutoStartRefused
            ? "node not running; start it with 'arcforges node run --background' or the Desktop"
            : exception.Message.TrimEnd('.') + (exception.Guidance.Length > 0 ? "; " + exception.Guidance : string.Empty);
        if (Json)
        {
            // A busy node is running: RESOURCE/overloaded (retry later), never "not running".
            var error = exception.Error ?? new ArcError
            {
                Category = exception.Reason switch
                {
                    NodeUnavailableReason.AccessDenied => ErrorCategory.Authorization,
                    NodeUnavailableReason.Busy => ErrorCategory.Resource,
                    _ => ErrorCategory.State,
                },
                Code = exception.Reason switch
                {
                    NodeUnavailableReason.AccessDenied => "permission_denied",
                    NodeUnavailableReason.Incompatible => "incompatible_version",
                    NodeUnavailableReason.Busy => "overloaded",
                    _ => "node_not_running",
                },
                Retry = exception.Reason == NodeUnavailableReason.Busy ? new RetryAdvice { Mode = RetryMode.AfterTime } : null,
                Effect = EffectCertainty.DidNotHappen,
            };
            error.MessageKey = error.MessageKey.Length > 0 ? error.MessageKey : "error." + error.Category.ToString().ToLowerInvariant() + "." + error.Code;

            // cli.md section 2: stdout carries only {"error": <ArcError JSON>}; the human sentence goes to stderr.
            Document(new JsonObject { ["error"] = ToJsonNode(error) });
            _error.WriteLine("arcforges: " + message);
        }
        else
        {
            _error.WriteLine("arcforges: " + message);
            if (exception.Reason == NodeUnavailableReason.AutoStartRefused)
            {
                Trace(exception.Message);
            }
        }

        return ExitCodes.For(exception);
    }

    /// <summary>Prints a usage error and returns 2.</summary>
    public int Usage(string message)
    {
        _error.WriteLine("error: " + message);
        _error.WriteLine("Run 'arcforges --help' for usage.");
        return ExitCodes.Usage;
    }

    private void WriteJson(JsonNode node, bool indented)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = indented, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            node.WriteTo(writer);
        }

        _out.WriteLine(Encoding.UTF8.GetString(buffer.ToArray()));
    }

    /// <summary>Replaces <c>{"value": "&lt;base64&gt;"}</c> under <c>*Id</c> and <c>*Ids</c> keys with base32 ID text.</summary>
    private static void RenderIds(JsonNode node)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var (key, child) in obj.ToList())
                {
                    if (child is null)
                    {
                        continue;
                    }

                    if (key.EndsWith("Id", StringComparison.Ordinal) && AsId(child) is { } text)
                    {
                        obj[key] = text;
                    }
                    else if (key.EndsWith("Ids", StringComparison.Ordinal) && child is JsonArray ids)
                    {
                        for (var i = 0; i < ids.Count; i++)
                        {
                            if (ids[i] is { } item && AsId(item) is { } idText)
                            {
                                ids[i] = idText;
                            }
                        }
                    }
                    else
                    {
                        RenderIds(child);
                    }
                }

                break;
            case JsonArray array:
                foreach (var item in array)
                {
                    if (item is not null)
                    {
                        RenderIds(item);
                    }
                }

                break;
        }
    }

    private static string? AsId(JsonNode node)
    {
        if (node is not JsonObject { Count: 1 } obj || obj["value"] is not JsonValue value || !value.TryGetValue<string>(out var base64))
        {
            return null;
        }

        var bytes = new byte[Base64.GetMaxDecodedFromUtf8Length(base64.Length)];
        return Convert.TryFromBase64String(base64, bytes, out var written) && written == 16 ? IdText.Format(bytes.AsSpan(0, 16)) : null;
    }

    private static int VisibleLength(string text) => text.Contains('\u001b', StringComparison.Ordinal)
        ? System.Text.RegularExpressions.Regex.Replace(text, "\u001b\\[[0-9;]*m", string.Empty).Length
        : text.Length;

    private static string Row(IReadOnlyList<string> cells, int[] widths)
    {
        var builder = new StringBuilder();
        for (var column = 0; column < widths.Length; column++)
        {
            var cell = cells[column];
            var visible = VisibleLength(cell);
            if (visible > widths[column])
            {
                cell = cell[..Math.Max(1, widths[column] - 1)] + "…";
                visible = widths[column];
            }

            builder.Append(cell);
            if (column < widths.Length - 1)
            {
                builder.Append(' ', widths[column] - visible + 2);
            }
        }

        return builder.ToString().TrimEnd();
    }
}

/// <summary>English messages of the error codes the CLI shows (catalogue: ArcForges-Design <c>errors.md</c>).</summary>
public static class Messages
{
    /// <summary>The message of an error (its code's text, or its message key).</summary>
    public static string For(ArcError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        var text = error.Code switch
        {
            "invalid_argument" => "invalid argument",
            "invalid_cursor" => "the cursor is malformed or from another stream generation",
            "incompatible_version" => "the client and the node speak incompatible contract versions",
            "permission_denied" => "permission denied",
            "approval_required" => "approval required",
            "revision_conflict" => "the settings changed since they were read; read them again",
            "command_id_reused" => "the command ID was reused with a different request",
            "not_found" => "not found",
            "invalid_state" => "the object's state does not allow this",
            "node_stopping" => "the node is stopping",
            "overloaded" => "the node is overloaded; retry shortly",
            "internal" => "the node failed unexpectedly",
            _ => error.MessageKey is { Length: > 0 } key ? key : error.Code,
        };
        if (error.Details?.State is { } state)
        {
            var resource = state.Resource is { } aggregate ? (aggregate.Kind + " " + IdText.Format(aggregate.Id)).Trim() : null;
            var detail = string.Join("; ", new[] { resource, state.State, state.Reason }.Where(part => !string.IsNullOrEmpty(part)));
            if (detail.Length > 0)
            {
                text += ": " + detail;
            }
        }

        return text;
    }

    /// <summary>The text of a count.</summary>
    public static string Count(long value) => value.ToString("N0", CultureInfo.InvariantCulture);
}
