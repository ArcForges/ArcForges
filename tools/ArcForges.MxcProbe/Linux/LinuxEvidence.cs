// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk.V1;

namespace ArcForges.MxcProbe.Linux;

// Evidence belongs to the trusted driver/owner, outside every workload grant.
// Each phase is flushed before the corresponding native action starts.
internal sealed class LinuxEvidence : IDisposable
{
    private const int MaximumBytes = 4 * 1024 * 1024;
    private readonly FileStream _stream;
    private readonly string _runId;
    private readonly string _path;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly object _gate = new();
    private int _sequence;
    private int _detailBytes;
    private int _detailSequence;

    internal LinuxEvidence(string path, string runId)
    {
        _runId = runId;
        _path = Path.GetFullPath(path);
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.Read,
            Options = FileOptions.WriteThrough
        };
        if (OperatingSystem.IsLinux()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        _stream = new FileStream(path, options);
        Phase("evidence_open", "ready");
    }

    internal void Phase(string phase, string outcome, Dictionary<string, string>? facts = null)
    {
        lock (_gate)
        {
            if (phase.Length > 96 || outcome.Length > 64 || facts?.Count > 32
                || facts?.Any(x => x.Key.Length > 96 || x.Value.Length > 1024) == true)
                throw new InvalidDataException("linux_evidence_field_bound");
            var entry = new LinuxEvidenceEntry(++_sequence, _runId, Environment.ProcessId,
                DateTimeOffset.UtcNow, _clock.Elapsed.TotalMilliseconds, phase, outcome, facts);
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(entry, LinuxEvidenceJson.Default.LinuxEvidenceEntry);
            if (_stream.Position + bytes.Length + 1 > MaximumBytes)
                throw new IOException("linux_evidence_size_bound");
            _stream.Write(bytes);
            _stream.WriteByte((byte)'\n');
            _stream.Flush(flushToDisk: true);
        }
    }

    internal void Failure(string phase, Exception ex, bool cleanup = false)
    {
        var facts = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["errorType"] = ex.GetType().Name,
            ["hresult"] = ex.HResult.ToString("X8", CultureInfo.InvariantCulture)
        };
        Exception? cause = ex;
        for (int depth = 0; depth < 3 && cause is not null; depth++, cause = cause.InnerException)
        {
            string prefix = "cause" + depth.ToString(CultureInfo.InvariantCulture);
            facts[prefix + "Type"] = cause.GetType().Name;
            facts[prefix + "Hresult"] = cause.HResult.ToString("X8", CultureInfo.InvariantCulture);
            if (cause is LinuxProbeException probe) facts[prefix + "Code"] = probe.Code;
            if (cause is MxcException mxc)
            {
                facts[prefix + "SdkCode"] = mxc.Code.ToString();
                facts[prefix + "SdkCodeValue"] = ((int)mxc.Code).ToString(CultureInfo.InvariantCulture);
                if (IsDiagnosticIdentifier(mxc.Operation)) facts[prefix + "SdkOperation"] = mxc.Operation!;
                if (IsDiagnosticIdentifier(mxc.NativeCode)) facts[prefix + "SdkNativeCode"] = mxc.NativeCode!;
            }
            if (cause is Win32Exception native)
                facts[prefix + "NativeCode"] = native.NativeErrorCode.ToString(CultureInfo.InvariantCulture);
            if (cause is SocketException socket)
                facts[prefix + "SocketCode"] = socket.SocketErrorCode.ToString();
        }
        // No exception message, raw argv/environment, or workload output is copied here.
        try { Phase(phase, cleanup ? "cleanup_failed" : "failed", facts); }
        catch (Exception evidenceError) when (evidenceError is IOException or UnauthorizedAccessException or InvalidDataException or ObjectDisposedException)
        {
            // Preserve the primary failure even if its evidence sink is full/lost.
            Console.Error.WriteLine("linux_evidence_write_failed:primary=" + ex.GetType().Name
                + ":primaryHresult=" + ex.HResult.ToString("X8", CultureInfo.InvariantCulture)
                + ":evidence=" + evidenceError.GetType().Name
                + ":evidenceHresult=" + evidenceError.HResult.ToString("X8", CultureInfo.InvariantCulture));
        }
    }

    // Used only for bounded output of fixed control tools or this probe's known
    // synthetic fixtures, never arbitrary user workloads or credentials.
    // A hash alone cannot diagnose an error; private detail is not trusted state.
    internal void Detail(string phase, string label, byte[] data)
    {
        lock (_gate)
        {
            if (data.Length > 65_536 || _detailBytes + data.Length > MaximumBytes
                || label.Length is < 1 or > 32 || label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_'))
                throw new LinuxProbeException("linux_evidence_detail_bound");
            string path = _path + "." + (++_detailSequence).ToString("D4", CultureInfo.InvariantCulture) + "." + label + ".txt";
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.Read };
            if (OperatingSystem.IsLinux()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(path, options))
            {
                stream.Write(data);
                stream.Flush(flushToDisk: true);
            }
            _detailBytes += data.Length;
            Phase(phase, "diagnostic_detail_saved", new(StringComparer.Ordinal)
            {
                ["detailFile"] = Path.GetFileName(path),
                ["bytes"] = data.Length.ToString(CultureInfo.InvariantCulture),
                ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(data))
            });
        }
    }

    public void Dispose() => _stream.Dispose();

    private static bool IsDiagnosticIdentifier(string? value) => value is { Length: > 0 and <= 128 }
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or ':' or '+');
}

internal sealed record LinuxCaseResult(string Id, bool Passed, Dictionary<string, string> Facts);
internal sealed class LinuxProbeException(string code, Exception? inner = null) : Exception(code, inner)
{
    internal string Code { get; } = code;
}
internal sealed record LinuxEvidenceEntry(int Sequence, string RunId, int ProcessId,
    DateTimeOffset Utc, double ElapsedMs, string Phase, string Outcome, Dictionary<string, string>? Facts);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(LinuxEvidenceEntry))]
[JsonSerializable(typeof(List<LinuxCaseResult>))]
internal sealed partial class LinuxEvidenceJson : JsonSerializerContext;
