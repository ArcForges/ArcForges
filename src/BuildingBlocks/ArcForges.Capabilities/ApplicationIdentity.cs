// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Capabilities;

/// <summary>Stable closed product identity; no platform, version or process component.</summary>
public sealed record AppIdentity
{
    private AppIdentity(string productId) => ProductId = productId;

    public static AppIdentity ArcScope { get; } = new("arcscope");
    public static AppIdentity Companion { get; } = new("companion");
    public string ProductId { get; }

    public static AppIdentity Parse(string productId) => productId switch
    {
        "arcscope" => ArcScope,
        "companion" => Companion,
        _ => throw new ArgumentException("An exact supported product identity is required.", nameof(productId)),
    };
}

/// <summary>Durable installation identity supplied by the owning application, independent of process lifetime.</summary>
public sealed record InstallationIdentity
{
    public InstallationIdentity(AppIdentity app, DeviceId deviceId, InstallationId installationId)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (deviceId.Value == Guid.Empty || installationId.Value == Guid.Empty)
        {
            throw new ArgumentException("Device and installation identities must be initialized.");
        }

        App = app;
        DeviceId = deviceId;
        InstallationId = installationId;
    }

    public AppIdentity App { get; }
    public DeviceId DeviceId { get; }
    public InstallationId InstallationId { get; }

    /// <summary>Returns a fresh generated contract value; mutable wire values cannot change the owner.</summary>
    public ApplicationScope ToApplicationScope() => new()
    {
        ProductId = App.ProductId,
        InstallationId = InstallationId.ToWire(),
    };
}

/// <summary>In-process owner identity. Delivery epoch is supplied by the installation's registration authority.</summary>
public sealed record InstanceIdentity
{
    public InstanceIdentity(InstallationIdentity installation, InstanceId instanceId, ulong? epoch)
    {
        ArgumentNullException.ThrowIfNull(installation);
        if (instanceId.Value == Guid.Empty)
        {
            throw new ArgumentException("Instance identity must be initialized.", nameof(instanceId));
        }

        ArgumentNullException.ThrowIfNull(epoch);
        Installation = installation;
        InstanceId = instanceId;
        Epoch = epoch.Value;
    }

    public InstallationIdentity Installation { get; }
    public InstanceId InstanceId { get; }
    public ulong Epoch { get; }
}
