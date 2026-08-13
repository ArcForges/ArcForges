// SPDX-License-Identifier: AGPL-3.0-only

using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Layout;
using Avalonia.Themes.Fluent;
using Avalonia.Threading;

namespace ArcChat.Desktop;

internal sealed class App : Avalonia.Application
{
    public override void Initialize()
    {
        Styles.Add(new FluentTheme());
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new Window
            {
                Title = "ArcChat Desktop",
                Width = 960,
                Height = 640,
                Content = new TextBlock
                {
                    Text = "Hello from ArcChat Desktop",
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                }
            };

            if (Program.IsSmoke)
            {
                Dispatcher.UIThread.Post(() =>
                {
                    bool initialized = desktop.MainWindow.Content is TextBlock text &&
                        string.Equals(text.Text, "Hello from ArcChat Desktop", StringComparison.Ordinal) &&
                        Styles.Count > 0;
                    Console.WriteLine("arcchat {0} arcforges-smoke avalonia-window", initialized ? "ok" : "failed");
                    desktop.Shutdown(initialized ? 0 : 1);
                }, DispatcherPriority.Loaded);
            }
        }

        base.OnFrameworkInitializationCompleted();
    }
}
