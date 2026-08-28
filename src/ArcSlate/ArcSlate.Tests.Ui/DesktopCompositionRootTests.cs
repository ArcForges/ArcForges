// SPDX-License-Identifier: AGPL-3.0-only

using ArcSlate.Desktop;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ArcSlate.Tests.Ui;

public sealed class DesktopCompositionRootTests
{
    private static DesktopHostOptions Options() => new()
    {
        ProductId = "arcslate",
        InstanceId = "test-instance",
        SmokeMode = true,
    };

    [Xunit.Fact]
    [Xunit.Trait("Category", "Ui")]
    public void CompositionRootPublishesTheHostedServiceRegistry()
    {
        ServiceCollection services = [];

        DesktopCompositionRoot.ConfigureServices(services, Options());

        using ServiceProvider provider = services.BuildServiceProvider();
        DesktopHostOptions resolved = provider.GetRequiredService<DesktopHostOptions>();
        Xunit.Assert.Equal("arcslate", resolved.ProductId);
        Xunit.Assert.NotNull(provider.GetRequiredService<DesktopHostedServiceRegistry>());
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Ui")]
    public void OnlyRegistryEntriesBecomeHostedServices()
    {
        ServiceCollection services = [];

        DesktopCompositionRoot.ConfigureServices(services, Options());

        using ServiceProvider provider = services.BuildServiceProvider();
        DesktopHostedServiceRegistry registry = provider.GetRequiredService<DesktopHostedServiceRegistry>();
        Xunit.Assert.Equal(
            registry.RegisteredServices.Count,
            provider.GetServices<IHostedService>().Count());
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Ui")]
    public void RegisteringTheSameHostedServiceTwiceIsAnOwnershipError()
    {
        DesktopHostedServiceRegistry registry = new();
        registry.Register(static _ => new ProbeHostedService());

        Xunit.Assert.Throws<InvalidOperationException>(
            () => registry.Register(static _ => new ProbeHostedService()));
    }

    private sealed class ProbeHostedService : IHostedService
    {
        public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
