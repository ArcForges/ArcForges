// SPDX-License-Identifier: AGPL-3.0-only
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Interactivity;
using Avalonia.Threading;

namespace ArcForges.Desktop.Tests;

public sealed class MainWindowTests
{
    [Fact]
    public async Task RealViewLoadsAndUpdatesThroughItsButton()
    {
        await using var session = HeadlessUnitTestSession.StartNew(typeof(HeadlessAppBuilder));
        await session.Dispatch(() =>
        {
            var window = new MainWindow();
            try
            {
                window.Show();
                var input = window.FindControl<TextBox>("NameInput")!;
                var button = window.FindControl<Button>("SayHelloButton")!;
                var greeting = window.FindControl<TextBlock>("GreetingText")!;

                Assert.Equal("ArcForges", window.Title);
                Assert.Equal("Hello, World!", greeting.Text);
                input.Text = "Ada";
                Dispatcher.UIThread.RunJobs();
                button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Dispatcher.UIThread.RunJobs();
                Assert.Equal("Hello, Ada!", greeting.Text);

                input.Text = " ";
                Dispatcher.UIThread.RunJobs();
                button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Dispatcher.UIThread.RunJobs();
                Assert.Equal("Hello, World!", greeting.Text);
            }
            finally
            {
                window.Close();
            }
        }, TestContext.Current.CancellationToken);
    }
}

public static class HeadlessAppBuilder
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions());
}
