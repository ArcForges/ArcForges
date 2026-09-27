// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Foundation;

/// <summary>Allocates identities using the published Contracts value types, without a second wire authority.</summary>
public static class IdentityGeneration
{
    public static RealmId NewRealm() => new(Guid.NewGuid());
    public static UserId NewUser() => new(Guid.NewGuid());
    public static WorkspaceId NewWorkspace() => new(Guid.NewGuid());
    public static DeviceId NewDevice() => new(Guid.NewGuid());
    public static InstallationId NewInstallation() => new(Guid.NewGuid());
    public static InstanceId NewInstance() => new(Guid.NewGuid());
    public static CommandId NewCommand() => new(Guid.NewGuid());
    public static CorrelationId NewCorrelation() => new(Guid.NewGuid());
    public static ResourceId NewResource() => new(Guid.NewGuid());
    public static BlobId NewBlob() => new(Guid.NewGuid());
    public static ArtifactId NewArtifact() => new(Guid.NewGuid());
    public static ContentOriginId NewContentOrigin() => new(Guid.NewGuid());
    public static ContentUnitId NewContentUnit() => new(Guid.NewGuid());
    public static ConflictId NewConflict() => new(Guid.NewGuid());
    public static DelegationId NewDelegation() => new(Guid.NewGuid());
}
