// SPDX-License-Identifier: AGPL-3.0-only

using Microsoft.Extensions.DependencyInjection;

namespace ArcSlate.Desktop;

/// <summary>
/// The one place where ArcSlate desktop services are registered. Steps 05+ add their
/// Application, Infrastructure and LocalRpc registrations here; long-running work goes through
/// <see cref="DesktopHostedServiceRegistry"/> and nowhere else.
/// </summary>
internal static class DesktopCompositionRoot
{
    /// <summary>Registers the desktop host graph and returns the same collection for chaining.</summary>
    public static IServiceCollection ConfigureServices(IServiceCollection services, DesktopHostOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        services.AddSingleton(options);

        DesktopHostedServiceRegistry registry = new();
        RegisterHostedServices(registry, options);
        services.AddSingleton(registry);
        registry.ApplyTo(services);

        return services;
    }

    /// <summary>
    /// The extension point owned by the steps that add ArcSlate background work. It is
    /// deliberately empty while Step 01 owns only the skeleton; adding a service here is the only
    /// supported way to get an <c>IHostedService</c> into the process.
    /// </summary>
    private static void RegisterHostedServices(DesktopHostedServiceRegistry registry, DesktopHostOptions options)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(options);
    }
}
