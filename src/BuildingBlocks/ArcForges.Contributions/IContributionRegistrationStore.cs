// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;

namespace ArcForges.Contributions;

/// <summary>
/// Owner-provided durable metadata store. Implementations partition by the exact installation,
/// atomically insert a new key, return AlreadyPresent for an identical record and throw on conflict.
/// </summary>
public interface IContributionRegistrationStore
{
    ContributionPersistenceResult Add(InstallationIdentity installation, ContributionDefinition definition);
}
