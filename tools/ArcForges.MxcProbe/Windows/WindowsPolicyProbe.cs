// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcForges.MxcProbe;

internal sealed record WindowsPolicyProbeResult(int ExitCode, bool JsonParsed, bool NativeBaseContainer,
    bool? NeedsDaclAugmentation, bool DenyPaths, bool IngressHostLoopback, bool UiRestrictionsComplete,
    string StdoutSha256, string StderrSha256);

internal static class WindowsPolicyProbe
{
    private static readonly string[] UiCapabilities = ["canBlockClipboardRead", "canBlockClipboardWrite", "canBlockInputInjection",
        "canBlockInputMethodChanges", "canBlockExternalUiObjects", "canBlockGlobalUiNamespace",
        "canBlockDesktopSwitching", "canBlockLogoffOrShutdown", "canBlockSystemParameterChanges", "canBlockDisplaySettingsChanges"];
    // Only --probe output is interpreted here. Payload terminal bytes are never
    // backend envelopes or trusted state, even when they contain identical JSON.
    internal static async Task<WindowsPolicyProbeResult> RunAsync(string stage, string privatePolicy, string evidenceStem)
    {
        var executor = Path.Combine(stage, "wxc-exec.exe");
        using var lease = File.Open(executor, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (Convert.ToHexStringLower(SHA256.HashData(lease)) != Program.WindowsNative["wxc-exec.exe"])
            throw new InvalidDataException("Probe executor differs from the pinned official artifact.");
        var start = new ProcessStartInfo(executor)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(privatePolicy)!,
        };
        start.ArgumentList.Add("--probe");
        start.ArgumentList.Add("--config");
        start.ArgumentList.Add(privatePolicy);
        start.Environment.Clear();
        start.Environment["SystemRoot"] = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.System))!;
        start.Environment["PATH"] = "";
        start.Environment["TEMP"] = start.WorkingDirectory;
        start.Environment["TMP"] = start.WorkingDirectory;
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Official probe did not start.");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var stdout = CaptureAsync(process.StandardOutput.BaseStream, deadline.Token);
        var stderr = CaptureAsync(process.StandardError.BaseStream, deadline.Token);
        byte[] output;
        byte[] errors;
        try
        {
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(deadline.Token)).ConfigureAwait(false);
            output = await stdout.ConfigureAwait(false);
            errors = await stderr.ConfigureAwait(false);
        }
        finally
        {
            if (!process.HasExited)
            {
                // --probe starts no payload. This exact retained process is ours.
                process.Kill();
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await process.WaitForExitAsync(cleanup.Token).ConfigureAwait(false);
            }
        }
        await SaveNewAsync(evidenceStem + ".stdout", output).ConfigureAwait(false);
        await SaveNewAsync(evidenceStem + ".stderr", errors).ConfigureAwait(false);
        var parsed = false;
        var native = false;
        bool? augmentation = null;
        var deny = false;
        var loopback = false;
        var ui = false;
        try
        {
            using var document = JsonDocument.Parse(output);
            var root = document.RootElement;
            parsed = root.ValueKind == JsonValueKind.Object;
            native = root.TryGetProperty("tier", out var tier) && tier.GetString() == "base-container";
            if (root.TryGetProperty("needsDaclAugmentation", out var dacl)
                && dacl.ValueKind is JsonValueKind.True or JsonValueKind.False) augmentation = dacl.GetBoolean();
            if (root.TryGetProperty("probes", out var probes))
            {
                deny = True(probes, "baseContainerSupportsDenyPaths");
                loopback = True(probes, "baseContainerSupportsIngressHostLoopbackAllow");
                if (probes.TryGetProperty("uiCapabilities", out var capabilities))
                    ui = UiCapabilities.All(name => True(capabilities, name));
            }
        }
        catch (JsonException) { /* Native rejection need not return a success envelope. */ }
        return new(process.ExitCode, parsed, native, augmentation, deny, loopback, ui,
            Convert.ToHexStringLower(SHA256.HashData(output)), Convert.ToHexStringLower(SHA256.HashData(errors)));
    }

    private static bool True(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object
        && value.TryGetProperty(name, out var member) && member.ValueKind == JsonValueKind.True;

    private static async Task<byte[]> CaptureAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var result = new MemoryStream();
        var buffer = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
        {
            if (result.Length + count > 65_536) throw new InvalidDataException("Official probe output exceeds the evidence bound.");
            result.Write(buffer, 0, count);
        }
        return result.ToArray();
    }

    private static async Task SaveNewAsync(string path, byte[] bytes)
    {
        await using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        await stream.WriteAsync(bytes).ConfigureAwait(false);
        stream.Flush(true);
    }
}
