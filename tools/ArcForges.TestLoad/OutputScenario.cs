// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;

namespace ArcForges.TestLoad;

/// <summary>
/// <c>output</c>: writes exactly <c>bytes</c> bytes of deterministic text at the maximum rate the
/// reader accepts. The text is lines of <c>line-bytes</c> bytes (base64-alphabet characters ending
/// in <c>\n</c>; the last line may be shorter). With <c>stream both</c>, even lines go to standard
/// output and odd lines to standard error; <c>none</c> only computes the expected digests.
/// <see cref="ScenarioReport.Digest"/> is the SHA-256 of the whole text, so a captured single
/// stream can be compared byte for byte with <c>sha256sum</c>.
/// </summary>
internal static class OutputScenario
{
    public const long MaxBytes = 1L << 40;
    public const long MaxLineBytes = 1 << 20;
    private const int ChunkBytes = 64 * 1024;
    private static readonly byte[] Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"u8.ToArray();

    public static ScenarioReport Run(ScenarioOptions options)
    {
        var totalBytes = options.GetInt64("bytes", 1024 * 1024, 0, MaxBytes);
        var lineBytes = options.GetInt64("line-bytes", 100, 1, MaxLineBytes);
        var stream = options.GetChoice("stream", "stdout", "stdout", "stderr", "both", "none");
        var seed = options.GetSeed();
        options.GetUnrecorded("report");
        options.EnsureAllUsed();

        var stopwatch = Stopwatch.StartNew();
        using var whole = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var stdoutHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var stderrHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var stdout = stream is "stdout" or "both" ? new BufferedStream(Console.OpenStandardOutput(), ChunkBytes) : null;
        using var stderr = stream is "stderr" or "both" ? new BufferedStream(Console.OpenStandardError(), ChunkBytes) : null;
        long stdoutBytes = 0, stderrBytes = 0;
        var buffer = new byte[(int)Math.Max(ChunkBytes, Math.Min(lineBytes, MaxLineBytes))];

        if (stream == "both")
        {
            for (var line = 0L; line * lineBytes < totalBytes; line++)
            {
                var offset = line * lineBytes;
                var length = (int)Math.Min(lineBytes, totalBytes - offset);
                var span = buffer.AsSpan(0, length);
                Fill(seed, lineBytes, offset, span);
                whole.AppendData(span);
                if (line % 2 == 0)
                {
                    stdout!.Write(span);
                    stdoutHash.AppendData(span);
                    stdoutBytes += length;
                }
                else
                {
                    stderr!.Write(span);
                    stderrHash.AppendData(span);
                    stderrBytes += length;
                }
            }
        }
        else
        {
            var target = stdout ?? stderr;
            for (var offset = 0L; offset < totalBytes; offset += ChunkBytes)
            {
                var span = buffer.AsSpan(0, (int)Math.Min(ChunkBytes, totalBytes - offset));
                Fill(seed, lineBytes, offset, span);
                whole.AppendData(span);
                target?.Write(span);
            }

            if (stream == "stdout")
            {
                stdoutBytes = totalBytes;
            }
            else if (stream == "stderr")
            {
                stderrBytes = totalBytes;
            }
        }

        stdout?.Flush();
        stderr?.Flush();
        stopwatch.Stop();

        var content = Deterministic.Hex(whole.GetHashAndReset());
        var streamDigests = new Dictionary<string, string>(StringComparer.Ordinal);
        if (stream == "both")
        {
            streamDigests["stdout"] = Deterministic.Hex(stdoutHash.GetHashAndReset());
            streamDigests["stderr"] = Deterministic.Hex(stderrHash.GetHashAndReset());
        }
        else if (stream != "none")
        {
            streamDigests[stream] = content;
        }

        return new ScenarioReport
        {
            Scenario = "output",
            Parameters = options.Parameters,
            Digest = content,
            Results = new Dictionary<string, long>(StringComparer.Ordinal)
            {
                ["bytes"] = totalBytes,
                ["lines"] = (totalBytes + lineBytes - 1) / lineBytes,
                ["stdoutBytes"] = stdoutBytes,
                ["stderrBytes"] = stderrBytes,
            },
            StreamDigests = streamDigests,
            Measured = Measurements.Collect(stopwatch),
        };
    }

    /// <summary>Writes the text at <paramref name="offset"/>; a pure function of seed, line length and position.</summary>
    public static void Fill(ulong seed, long lineBytes, long offset, Span<byte> destination)
    {
        var column = offset % lineBytes;
        var block = (ulong)offset / 8;
        var shift = (int)(offset % 8) * 6;
        var bits = Deterministic.Mix(seed, block);
        for (var i = 0; i < destination.Length; i++)
        {
            destination[i] = column == lineBytes - 1 ? (byte)'\n' : Alphabet[(int)((bits >> shift) & 63)];
            if (++column == lineBytes)
            {
                column = 0;
            }

            shift += 6;
            if (shift == 48)
            {
                shift = 0;
                bits = Deterministic.Mix(seed, ++block);
            }
        }
    }
}
