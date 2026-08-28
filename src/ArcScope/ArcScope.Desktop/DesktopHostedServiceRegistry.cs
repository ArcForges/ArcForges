// SPDX-License-Identifier: AGPL-3.0-only

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ArcScope.Desktop;

/// <summary>
/// The single explicit seam through which ArcScope background work reaches the desktop host.
/// Later steps register their hosted services here instead of calling
/// <see cref="IServiceCollection"/> directly, so the set of long-running services in the
/// process stays enumerable and duplicate ownership fails loudly.
/// </summary>
internal sealed class DesktopHostedServiceRegistry
{
    private readonly Dictionary<Type, Func<IServiceProvider, IHostedService>> _factories = [];

    /// <summary>The hosted service types registered so far. Order is not part of the contract.</summary>
    public IReadOnlyCollection<Type> RegisteredServices => _factories.Keys;

    /// <summary>
    /// Registers one hosted service. Registering the same type twice is an ownership error and
    /// throws rather than silently running two copies.
    /// </summary>
    public DesktopHostedServiceRegistry Register<TService>(Func<IServiceProvider, TService> factory)
        where TService : class, IHostedService
    {
        ArgumentNullException.ThrowIfNull(factory);

        if (!_factories.TryAdd(typeof(TService), factory))
        {
            throw new InvalidOperationException(
                $"{typeof(TService)} is already registered with the ArcScope hosted-service registry.");
        }

        return this;
    }

    /// <summary>Projects every registered factory onto the container as an <see cref="IHostedService"/>.</summary>
    internal void ApplyTo(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        foreach (Func<IServiceProvider, IHostedService> factory in _factories.Values)
        {
            services.AddSingleton(factory);
        }
    }
}
