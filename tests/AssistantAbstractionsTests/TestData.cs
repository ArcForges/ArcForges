// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Assistant.Abstractions;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using IdentityGeneration = ArcForges.Foundation.IdentityGeneration;

namespace AssistantAbstractionsTests;

/// <summary>Deterministic identities and references. Values are test-only and never leave the process.</summary>
internal static class TestData
{
    public static readonly AssistantProfileId Profile = new(new Guid("30000000-0000-0000-0000-000000000001"));
    public static readonly AssistantProfileId OtherProfile = new(new Guid("30000000-0000-0000-0000-000000000002"));

    public static string PlatformRoot { get; } = Path.Combine(Path.GetTempPath(), "ArcForgesAssistantTests");

    public static AssistantInstallationIdentity Installed(AssistantProductIdentity? product = null, int installation = 1)
        => new(product ?? AssistantProductIdentity.ArcScope,
            new InstallationId(new Guid($"20000000-0000-0000-0000-{installation:D12}")));

    public static AssistantHostIdentity Host(AssistantInstallationIdentity? installation = null, int instance = 1,
        ulong epoch = 7)
        => new(installation ?? Installed(), new InstanceId(new Guid($"40000000-0000-0000-0000-{instance:D12}")), epoch);

    public static AssistantHostOptions Options(AssistantHostIdentity owner, AssistantProfileId? profile = null,
        IEnumerable<AssistantPresentationMode>? modes = null)
        => new(owner, profile ?? Profile, PlatformRoot, "ArcScope", "assistant.arcscope",
            modes ?? [AssistantPresentationMode.Docked, AssistantPresentationMode.Floating]);

    public static AssistantActionRegistry Registry(AssistantHostIdentity owner)
        => new(owner, ["measurements.read", "annotations.append"], ["measurements.read", "annotations.write"]);

    public static AssistantActionDescriptor Descriptor(string operation = "measurements.read",
        string capability = "measurements.read")
        => new(operation, operation + ".title", operation + ".description", ["resource.selection"], [capability],
            "availability." + operation);

    public static ResourceRef Resource(string owner = "arcscope", string? kind = null) => new()
    {
        RealmId = IdentityGeneration.NewRealm().ToWire(),
        WorkspaceId = IdentityGeneration.NewWorkspace().ToWire(),
        OwnerAppId = owner,
        ResourceKind = kind ?? owner + ".capture",
        ResourceId = IdentityGeneration.NewResource().ToWire(),
        Availability = ResourceAvailability.AvailableOffline,
    };

    public static ResourceVersionRef Version(string owner = "arcscope", string? kind = null, char hash = 'a')
        => new()
        {
            Resource = Resource(owner, kind),
            Cloud = new Revision { Value = 42 },
            ContentHash = new string(hash, 64),
        };

    public static AssistantResourceReference Reference(string owner = "arcscope", string? kind = null, char hash = 'a')
        => new(Version(owner, kind, hash));

    public static HostContextSelection Selection(AssistantResourceReference? resource = null, uint items = 1,
        ulong bytes = 1024, ContextSelectionId? id = null)
        => new(id ?? ContextSelectionId.New(), resource ?? Reference(), "selection.capture", items, bytes);
}
