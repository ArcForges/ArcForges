// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Assistant.Abstractions;

/// <summary>A stable, closed product identity. Platform and process details are never product IDs.</summary>
public sealed record AssistantProductIdentity
{
    private AssistantProductIdentity(string productId) => ProductId = productId;

    public static AssistantProductIdentity ArcScope { get; } = new("arcscope");
    public static AssistantProductIdentity Companion { get; } = new("companion");

    public string ProductId { get; }

    public static AssistantProductIdentity Parse(string productId) => productId switch
    {
        "arcscope" => ArcScope,
        "companion" => Companion,
        _ => throw new ArgumentException("An exact supported product identity is required.", nameof(productId)),
    };
}

/// <summary>Durable identity for one installation of exactly one product.</summary>
public sealed record AssistantInstallationIdentity
{
    public AssistantInstallationIdentity(AssistantProductIdentity product, InstallationId installationId)
    {
        ArgumentNullException.ThrowIfNull(product);
        if (installationId.Value == Guid.Empty)
        {
            throw new ArgumentException("Installation identity must be initialized.", nameof(installationId));
        }

        Product = product;
        InstallationId = installationId;
    }

    public AssistantProductIdentity Product { get; }
    public InstallationId InstallationId { get; }
}

/// <summary>One live, explicitly composed assistant host instance.</summary>
public sealed record AssistantHostIdentity
{
    public AssistantHostIdentity(AssistantInstallationIdentity installation, InstanceId instanceId, ulong epoch)
    {
        ArgumentNullException.ThrowIfNull(installation);
        if (instanceId.Value == Guid.Empty)
        {
            throw new ArgumentException("Instance identity must be initialized.", nameof(instanceId));
        }

        if (epoch == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(epoch), "A live host instance requires a positive epoch.");
        }

        Installation = installation;
        InstanceId = instanceId;
        Epoch = epoch;
    }

    public AssistantInstallationIdentity Installation { get; }
    public AssistantProductIdentity Product => Installation.Product;
    public InstanceId InstanceId { get; }
    public ulong Epoch { get; }
}

/// <summary>A profile partition key, independent of a window or process lifetime.</summary>
public readonly record struct AssistantProfileId
{
    public AssistantProfileId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Profile identity must be initialized.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    public static AssistantProfileId New() => new(Guid.NewGuid());
}

/// <summary>A typed data-store boundary. Its product, installation and profile cannot be reassigned.</summary>
public sealed record AssistantStorePartition
{
    public AssistantStorePartition(AssistantInstallationIdentity installation, AssistantProfileId profile)
    {
        ArgumentNullException.ThrowIfNull(installation);
        if (profile.Value == Guid.Empty)
        {
            throw new ArgumentException("Profile identity must be initialized.", nameof(profile));
        }

        Installation = installation;
        Profile = profile;
    }

    public AssistantInstallationIdentity Installation { get; }
    public AssistantProductIdentity Product => Installation.Product;
    public AssistantProfileId Profile { get; }
}

/// <summary>
/// Product-owned root derived from the platform root, never selected as an arbitrary sibling product path.
/// The directory layout is <c>&lt;platform root&gt;/&lt;product id&gt;/&lt;installation id&gt;/profiles/&lt;profile id&gt;</c>;
/// product, installation and profile identities are validated typed values, so no caller-chosen segment
/// can alias another product, installation or profile.
/// </summary>
public sealed class AssistantDataRoot
{
    private AssistantDataRoot(AssistantInstallationIdentity installation, string installationDirectory)
    {
        Installation = installation;
        InstallationDirectory = installationDirectory;
    }

    public AssistantInstallationIdentity Installation { get; }
    public AssistantProductIdentity Product => Installation.Product;

    /// <summary>The absolute directory owned by exactly this product installation.</summary>
    public string InstallationDirectory { get; }

    /// <summary>Derives the one installation directory beneath an absolute, platform-owned root.</summary>
    public static AssistantDataRoot ForApplication(string platformDataRoot, AssistantInstallationIdentity installation)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(platformDataRoot);
        ArgumentNullException.ThrowIfNull(installation);
        if (!System.IO.Path.IsPathFullyQualified(platformDataRoot))
        {
            throw new ArgumentException("An absolute platform data root is required.", nameof(platformDataRoot));
        }

        string platformRoot = System.IO.Path.GetFullPath(platformDataRoot);
        string installationDirectory = System.IO.Path.GetFullPath(System.IO.Path.Combine(platformRoot,
            installation.Product.ProductId,
            installation.InstallationId.Value.ToString("N", System.Globalization.CultureInfo.InvariantCulture)));
        return new AssistantDataRoot(installation, installationDirectory);
    }

    public AssistantStorePartition ForProfile(AssistantProfileId profile) => new(Installation, profile);

    /// <summary>Resolves the directory of one profile partition; a partition of another installation is refused.</summary>
    public string GetProfileDirectory(AssistantStorePartition partition)
    {
        ArgumentNullException.ThrowIfNull(partition);
        if (partition.Installation != Installation)
        {
            throw new ArgumentException("The partition belongs to a different product installation.", nameof(partition));
        }

        return System.IO.Path.Combine(InstallationDirectory, "profiles",
            partition.Profile.Value.ToString("N", System.Globalization.CultureInfo.InvariantCulture));
    }
}
