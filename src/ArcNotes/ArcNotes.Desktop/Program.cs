// SPDX-License-Identifier: AGPL-3.0-only

using Avalonia;

namespace ArcNotes.Desktop;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Contains("--smoke", StringComparer.Ordinal))
        {
            Console.WriteLine(string.Join(' ', "arcnotes", "ok", "arcforges-smoke", "hello"));
            return 0;
        }

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        return 0;
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>().UsePlatformDetect().LogToTrace();
}
