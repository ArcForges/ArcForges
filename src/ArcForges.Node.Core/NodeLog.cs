// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;
using System.Text.Json;
using ArcForges.Contracts.Node.V1;
using ArcForges.Observability;

namespace ArcForges.Node.Core;

/// <summary>One field of a log record.</summary>
/// <param name="Name">The field name; a name the redaction processor knows as sensitive is written as <c>[redacted]</c>.</param>
/// <param name="Value">A string, number, boolean or null.</param>
public readonly record struct LogField(string Name, object? Value);

/// <summary>
/// The node's structured log (architecture 02 section 5): JSON Lines in <c>&lt;data root&gt;/logs/node/</c>, rotated at 10 MB with 5
/// files kept. Every field passes through the DesktopPlatform <c>ArcForges.Observability</c> redaction processor before it is written:
/// a field whose name is known-sensitive (token, secret, password, prompt, path, environment and command content, and the other
/// reviewed names) is written as <c>[redacted]</c>, an exception is recorded only as its registered reason code
/// (<see cref="ExceptionReasonMapper"/>) and type name, never its message, and an event name that is not a dotted identifier is
/// written as <c>redacted</c>. Command lines and environment values are logged only at debug level, and only through these rules.
/// </summary>
public sealed class NodeLog : IDisposable
{
    /// <summary>The rotation size (10 MB).</summary>
    public const long DefaultMaxBytes = 10_000_000;

    /// <summary>The number of files kept (the current one included).</summary>
    public const int DefaultFiles = 5;

    /// <summary>The value written for a redacted field.</summary>
    public const string Redacted = "[redacted]";

    private readonly Lock _gate = new();
    private readonly string _directory;
    private readonly long _maxBytes;
    private readonly int _files;
    private readonly TimeProvider _clock;
    private FileStream? _stream;
    private bool _disposed;

    /// <summary>Opens (or creates) the log in <paramref name="directory"/>.</summary>
    public NodeLog(string directory, LogLevel minimum, TimeProvider? clock = null, long maxBytes = DefaultMaxBytes, int files = DefaultFiles)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxBytes, 1024);
        ArgumentOutOfRangeException.ThrowIfLessThan(files, 1);
        _directory = directory;
        _maxBytes = maxBytes;
        _files = files;
        _clock = clock ?? TimeProvider.System;
        MinimumLevel = minimum == LogLevel.Unspecified ? LogLevel.Info : minimum;
        Directory.CreateDirectory(directory);
    }

    /// <summary>The current file, <c>node.log</c>; older files are <c>node.1.log</c> (newest) to <c>node.4.log</c>.</summary>
    public string CurrentFile => Path.Combine(_directory, "node.log");

    /// <summary>The most detailed level written (records above it are dropped). Changes apply at once.</summary>
    public LogLevel MinimumLevel { get; set; }

    /// <summary>True when a record of <paramref name="level"/> is written.</summary>
    public bool IsEnabled(LogLevel level) => level != LogLevel.Unspecified && level <= MinimumLevel;

    /// <summary>Writes an error record.</summary>
    public void Error(string eventName, params ReadOnlySpan<LogField> fields) => Write(LogLevel.Error, eventName, fields);

    /// <summary>Writes an error record for an exception: its reason code and type only.</summary>
    public void Error(string eventName, Exception exception, params ReadOnlySpan<LogField> fields)
    {
        ArgumentNullException.ThrowIfNull(exception);
        LogField[] all = [.. fields, new("reason", ExceptionReasonMapper.Default.Map(exception)?.Code ?? "cancelled"), new("errorType", exception.GetType().Name)];
        Write(LogLevel.Error, eventName, all);
    }

    /// <summary>Writes a warning record.</summary>
    public void Warning(string eventName, params ReadOnlySpan<LogField> fields) => Write(LogLevel.Warning, eventName, fields);

    /// <summary>Writes an informational record.</summary>
    public void Info(string eventName, params ReadOnlySpan<LogField> fields) => Write(LogLevel.Info, eventName, fields);

    /// <summary>Writes a debug record.</summary>
    public void Debug(string eventName, params ReadOnlySpan<LogField> fields) => Write(LogLevel.Debug, eventName, fields);

    /// <summary>Writes one record when <paramref name="level"/> is enabled.</summary>
    public void Write(LogLevel level, string eventName, params ReadOnlySpan<LogField> fields)
    {
        if (!IsEnabled(level))
        {
            return;
        }

        var line = Format(_clock.GetUtcNow(), level, eventName, fields);
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            try
            {
                var stream = _stream ??= Open();
                if (stream.Length + line.Length > _maxBytes && stream.Length > 0)
                {
                    Rotate();
                    stream = _stream = Open();
                }

                stream.Write(line);
                stream.Flush();
            }
            catch (IOException)
            {
                // Logging never stops the node; a full or failing disk drops the record.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    /// <summary>Closes the current file.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            _stream?.Dispose();
            _stream = null;
        }
    }

    /// <summary>Formats one JSON Lines record (exposed for tests of the redaction rules).</summary>
    internal static byte[] Format(DateTimeOffset at, LogLevel level, string eventName, ReadOnlySpan<LogField> fields)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("at", at.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture));
            writer.WriteString("level", NodeConfiguration.FormatLogLevel(level));
            writer.WriteString("event", IsEventName(eventName) ? eventName : "redacted");
            writer.WriteStartObject("fields");
            foreach (var field in fields)
            {
                var name = string.IsNullOrWhiteSpace(field.Name) ? "unnamed" : field.Name;
                if (RedactionProcessor.IsSensitiveFieldName(name) || IsCommandOrEnvironment(name))
                {
                    writer.WriteString(name, Redacted);
                    continue;
                }

                switch (field.Value)
                {
                    case null:
                        writer.WriteNull(name);
                        break;
                    case string text:
                        writer.WriteString(name, text);
                        break;
                    case bool flag:
                        writer.WriteBoolean(name, flag);
                        break;
                    case int number:
                        writer.WriteNumber(name, number);
                        break;
                    case long number:
                        writer.WriteNumber(name, number);
                        break;
                    case uint number:
                        writer.WriteNumber(name, number);
                        break;
                    case ulong number:
                        writer.WriteNumber(name, number);
                        break;
                    case double number when double.IsFinite(number):
                        writer.WriteNumber(name, number);
                        break;
                    case Enum value:
                        writer.WriteString(name, value.ToString());
                        break;
                    default:
                        writer.WriteString(name, Convert.ToString(field.Value, CultureInfo.InvariantCulture));
                        break;
                }
            }

            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        buffer.WriteByte((byte)'\n');
        return buffer.ToArray();
    }

    /// <summary>
    /// The node's own sensitive field names on top of the Observability list: command lines, arguments and environment values
    /// (02 section 5; R-EXE-017), which may carry secrets and are never written as given.
    /// </summary>
    private static bool IsCommandOrEnvironment(string name)
    {
        var words = new List<string>();
        var start = 0;
        for (var i = 1; i <= name.Length; i++)
        {
            if (i == name.Length || !char.IsLetterOrDigit(name[i]) || (char.IsUpper(name[i]) && char.IsLower(name[i - 1])))
            {
                if (i > start)
                {
                    words.Add(name[start..i].Trim('_', '-', '.', ' ').ToLowerInvariant());
                }

                start = i < name.Length && !char.IsLetterOrDigit(name[i]) ? i + 1 : i;
            }
        }

        return words.Any(word => word is "command" or "commandline" or "cmd" or "cmdline" or "argv" or "args" or "arguments" or "env"
            or "environment" or "variables");
    }

    private static bool IsEventName(string? name)
    {
        if (name is not { Length: > 0 and <= 80 })
        {
            return false;
        }

        var wordStart = true;
        foreach (var character in name)
        {
            if (character == '.')
            {
                if (wordStart)
                {
                    return false;
                }

                wordStart = true;
            }
            else if (char.IsAsciiLetter(character) || character == '_' || (!wordStart && char.IsAsciiDigit(character)))
            {
                wordStart = false;
            }
            else
            {
                return false;
            }
        }

        return !wordStart;
    }

    private FileStream Open()
    {
        var stream = new FileStream(CurrentFile, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        return stream;
    }

    private void Rotate()
    {
        _stream?.Dispose();
        _stream = null;
        for (var index = _files - 1; index >= 1; index--)
        {
            var source = index == 1 ? CurrentFile : Numbered(index - 1);
            var target = Numbered(index);
            if (index == _files - 1 && File.Exists(target))
            {
                File.Delete(target);
            }

            if (File.Exists(source))
            {
                File.Move(source, target, overwrite: true);
            }
        }

        if (_files == 1 && File.Exists(CurrentFile))
        {
            File.Delete(CurrentFile);
        }
    }

    private string Numbered(int index) => Path.Combine(_directory, string.Create(CultureInfo.InvariantCulture, $"node.{index}.log"));

    /// <summary>A short, single-line text for a log field (no line breaks; at most 200 characters).</summary>
    public static string OneLine(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(Math.Min(text.Length, 200));
        foreach (var character in text)
        {
            if (builder.Length == 200)
            {
                break;
            }

            builder.Append(char.IsControl(character) ? ' ' : character);
        }

        return builder.ToString();
    }
}
