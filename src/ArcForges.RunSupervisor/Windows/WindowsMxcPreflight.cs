// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Node.Platform.Windows;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.RunSupervisor;

[SupportedOSPlatform("windows")]
internal static class WindowsMxcPreflight
{
    private static readonly string[] UiCapabilities = ["canBlockClipboardRead", "canBlockClipboardWrite", "canBlockInputInjection",
        "canBlockInputMethodChanges", "canBlockExternalUiObjects", "canBlockGlobalUiNamespace", "canBlockDesktopSwitching",
        "canBlockLogoffOrShutdown", "canBlockSystemParameterChanges", "canBlockDisplaySettingsChanges"];

    internal static async ValueTask CheckAsync(WindowsMxcStage stage, string policy, string control, WindowsMxcJob aggregate,
        WindowsMxcJob payload, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        using var io = WindowsRunIo.Create(interactive: false);
        using var process = WindowsMxcProcess.CreateSuspended(stage.Executor, ["--probe", "--config", policy],
            stage.Directory, WindowsMxcProcess.TrustedEnvironment(control), payload, standard: io.Standard);
        io.ReleaseRemoteEnds();
        io.CloseInput();
        _ = WindowsMxcProcess.RequireIdentity(process, stage.Executor);
        aggregate.RequireMember(process);
        payload.RequireMember(process);
        _ = payload.RequireOnly(process.ProcessId);
        var output = CaptureAsync(io.Output, timeout.Token);
        var stderr = CaptureAsync(io.Error!, timeout.Token);
        try
        {
            WindowsMxcProcess.Resume(process);
            var exited = WaitAsync(process, timeout.Token);
            await Task.WhenAll(output, stderr, exited).ConfigureAwait(false);
            var code = await exited.ConfigureAwait(false);
            _ = await payload.WaitForDrainAsync(null, TimeSpan.FromSeconds(5), timeout.Token).ConfigureAwait(false);
            _ = aggregate.RequireOnly(Environment.ProcessId);
            // These bytes are the isolated fixed-role --probe, never the workload streams.
            if (code != 0 || !Admitted(await output.ConfigureAwait(false)))
            {
                throw new RunNativeException("windows_mxc_preflight", "official_probe_exit:" + code.ToString(CultureInfo.InvariantCulture),
                    boundaryEmptyVerified: true, payloadNotStarted: true);
            }
        }
        finally
        {
            await timeout.CancelAsync().ConfigureAwait(false);
        }
    }

    private static bool Admitted(byte[] bytes)
    {
        try
        {
            using var json = JsonDocument.Parse(bytes);
            var root = json.RootElement;
            return root.ValueKind == JsonValueKind.Object
                && root.TryGetProperty("tier", out var tier) && tier.ValueKind == JsonValueKind.String && tier.GetString() == "base-container"
                && root.TryGetProperty("needsDaclAugmentation", out var augmentation) && augmentation.ValueKind == JsonValueKind.False
                && root.TryGetProperty("probes", out var probes) && True(probes, "baseContainerSupportsDenyPaths")
                && probes.TryGetProperty("uiCapabilities", out var ui) && UiCapabilities.All(name => True(ui, name));
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool True(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object
        && value.TryGetProperty(name, out var member) && member.ValueKind == JsonValueKind.True;

    private static async Task<uint> WaitAsync(LaunchedProcess process, CancellationToken cancellationToken)
    {
        while (WindowsMxcProcess.PollExit(process) is null)
        {
            await Task.Delay(20, cancellationToken).ConfigureAwait(false);
        }

        return WindowsMxcProcess.PollExit(process)!.Value;
    }

    private static async Task<byte[]> CaptureAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var capture = new MemoryStream();
        var buffer = new byte[4096];
        while (await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false) is var count && count > 0)
        {
            if (capture.Length + count > 65_536) throw new InvalidDataException("The official MXC probe exceeded its native report bound.");
            capture.Write(buffer, 0, count);
        }

        return capture.ToArray();
    }
}
