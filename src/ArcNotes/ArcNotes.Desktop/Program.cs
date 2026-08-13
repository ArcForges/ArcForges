// SPDX-License-Identifier: AGPL-3.0-only

using Avalonia;

namespace ArcNotes.Desktop;

internal static class Program
{
    internal static bool IsSmoke { get; private set; }

    [STAThread]
    public static int Main(string[] args)
    {
        IsSmoke = args.Contains("--smoke", StringComparer.Ordinal);
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        return Environment.ExitCode;
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>().UsePlatformDetect().LogToTrace();
}
