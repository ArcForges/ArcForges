// SPDX-License-Identifier: AGPL-3.0-only

using Avalonia;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ArcChat.Desktop;

internal static class Program
{
    internal static bool IsSmoke { get; private set; }

    [STAThread]
    public static int Main(string[] args)
    {
        IsSmoke = args.Contains("--smoke", StringComparer.Ordinal);

        DesktopHostOptions options = new()
        {
            ProductId = "arcchat",
            InstanceId = Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            SmokeMode = IsSmoke,
        };

        HostApplicationBuilder builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = args,
        });
        DesktopCompositionRoot.ConfigureServices(builder.Services, options);

        using IHost host = builder.Build();
        host.Start();
        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        finally
        {
            host.StopAsync().GetAwaiter().GetResult();
        }

        return Environment.ExitCode;
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>().UsePlatformDetect().LogToTrace();
}
