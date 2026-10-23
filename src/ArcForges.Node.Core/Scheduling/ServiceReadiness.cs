// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using System.Text.RegularExpressions;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;

namespace ArcForges.Node.Core.Scheduling;

/// <summary>What a readiness check found.</summary>
public enum ReadinessOutcome
{
    /// <summary>Not ready yet.</summary>
    Waiting,

    /// <summary>The condition holds.</summary>
    Ready,

    /// <summary><c>readiness_timeout</c> passed without the condition.</summary>
    TimedOut,
}

/// <summary>
/// The readiness condition of a <c>SERVICE</c> task (04 section 8; R-EXE-005): <c>output_regex</c> (the RE2-compatible subset, matched
/// line by line on either stream as output arrives), <c>tcp_listen_port</c> (a loopback or wildcard listener owned by one of the
/// service's processes) or <c>file_exists</c>, within <c>readiness_timeout</c> (default 120 s) from the start. The enforcement loop
/// checks it every tailer cycle; the port and the file every 500 ms.
/// </summary>
public sealed class ServiceReadiness
{
    /// <summary>The default <c>readiness_timeout</c>.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(120);

    /// <summary>
    /// The longest line the regex is matched against: a longer line is matched by its first 64 KiB, and the rest of it, up to its newline,
    /// is skipped (never joined to later output).
    /// </summary>
    public const int MaxLine = 64 * 1024;

    private static readonly TimeSpan ProbeInterval = TimeSpan.FromMilliseconds(500);
    private readonly Regex? _regex;
    private readonly int? _port;
    private readonly string? _file;
    private readonly long[] _offsets = new long[2];
    private readonly StringBuilder[] _partial = [new(), new()];

    // Each stream is decoded as a stream: a UTF-8 sequence split across two reads is decoded whole on the second.
    private readonly Decoder[] _decoders = [Encoding.UTF8.GetDecoder(), Encoding.UTF8.GetDecoder()];

    // A line longer than MaxLine was matched by its first MaxLine characters; its rest is skipped up to its newline.
    private readonly bool[] _skipping = new bool[2];
    private long _lastProbe = long.MinValue;

    private ServiceReadiness(Regex? regex, int? port, string? file, TimeSpan timeout)
    {
        _regex = regex;
        _port = port;
        _file = file;
        Timeout = timeout;
    }

    /// <summary>The timeout.</summary>
    public TimeSpan Timeout { get; }

    /// <summary>The condition in words (for the record).</summary>
    public string Describe() => _regex is not null ? $"output matched /{_regex}/" : _port is { } port ? $"a listener on TCP port {port}" : $"{_file} exists";

    /// <summary>The readiness of a spec, or <see langword="null"/> when it has none (a COMMAND, or a SERVICE without a condition).</summary>
    public static ServiceReadiness? For(TaskSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.Kind != TaskKind.Service || spec.Readiness is not { } readiness || readiness.ConditionCase == ReadinessCondition.ConditionOneofCase.None)
        {
            return null;
        }

        var timeout = readiness.HasReadinessTimeoutMs ? TimeSpan.FromMilliseconds(readiness.ReadinessTimeoutMs) : DefaultTimeout;
        return readiness.ConditionCase switch
        {
            ReadinessCondition.ConditionOneofCase.OutputRegex => new ServiceReadiness(Compile(readiness.OutputRegex), null, null, timeout),
            ReadinessCondition.ConditionOneofCase.TcpListenPort => new ServiceReadiness(null, (int)readiness.TcpListenPort, null, timeout),
            _ => new ServiceReadiness(null, null, readiness.FileExists, timeout),
        };
    }

    /// <summary>The RE2-compatible subset: the non-backtracking engine (linear time; no backreferences or lookarounds).</summary>
    public static Regex Compile(string pattern) => new(pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    /// <summary>
    /// Checks the condition: new output since the last check (regex), the listener or the file. <paramref name="elapsed"/> is the time since
    /// the attempt started (paused time excluded).
    /// </summary>
    public ReadinessOutcome Check(AttemptFiles files, IExecutionPlatform? platform, Func<IReadOnlyCollection<int>> processIds, TimeSpan elapsed, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(clock);
        if (_regex is not null)
        {
            if (Scan(files, OutputStreamKind.Stdout, 0) || Scan(files, OutputStreamKind.Stderr, 1))
            {
                return ReadinessOutcome.Ready;
            }
        }
        else if (_lastProbe == long.MinValue || clock.GetElapsedTime(_lastProbe) >= ProbeInterval)
        {
            _lastProbe = clock.GetTimestamp();
            if (_port is { } port ? platform?.Listens(port, processIds()) == true : File.Exists(_file) || Directory.Exists(_file))
            {
                return ReadinessOutcome.Ready;
            }
        }

        return elapsed >= Timeout ? ReadinessOutcome.TimedOut : ReadinessOutcome.Waiting;
    }

    /// <summary>Reads the stream's new bytes (at most 1 MiB per check) and matches each completed line, then the pending partial line.</summary>
    private bool Scan(AttemptFiles files, OutputStreamKind stream, int slot)
    {
        var path = files.OutputPath(stream);
        byte[] chunk;
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (file.Length <= _offsets[slot])
            {
                return false;
            }

            file.Position = _offsets[slot];
            chunk = new byte[(int)Math.Min(file.Length - _offsets[slot], 1024 * 1024)];
            var read = file.Read(chunk);
            Array.Resize(ref chunk, read);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }

        _offsets[slot] += chunk.Length;
        var decoder = _decoders[slot];
        var decoded = new char[decoder.GetCharCount(chunk, 0, chunk.Length, flush: false)];
        decoder.GetChars(chunk, 0, chunk.Length, decoded, 0, flush: false);
        var from = 0;
        if (_skipping[slot])
        {
            var end = Array.IndexOf(decoded, '\n');
            if (end < 0)
            {
                return false;
            }

            _skipping[slot] = false;
            from = end + 1;
        }

        var partial = _partial[slot];
        partial.Append(decoded, from, decoded.Length - from);
        var text = partial.ToString();
        var start = 0;
        while (true)
        {
            var newline = text.IndexOf('\n', start);
            if (newline < 0)
            {
                break;
            }

            if (Matches(text.AsSpan(start, newline - start).TrimEnd('\r')))
            {
                return true;
            }

            start = newline + 1;
        }

        partial.Clear();
        if (text.Length - start > MaxLine)
        {
            // The pending line outgrew MaxLine: it is matched by its first MaxLine characters once, and the rest of it is skipped.
            _skipping[slot] = true;
            return Matches(text.AsSpan(start, MaxLine));
        }

        partial.Append(text.AsSpan(start));
        return partial.Length > 0 && Matches(partial.ToString());
    }

    private bool Matches(ReadOnlySpan<char> line) => _regex!.IsMatch(line.Length > MaxLine ? line[..MaxLine] : line);
}
