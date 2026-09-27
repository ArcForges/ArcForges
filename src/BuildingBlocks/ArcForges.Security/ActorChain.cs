// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;

namespace ArcForges.Security;

/// <summary>
/// Complete immutable provenance constructed at entry and passed explicitly through every layer.
/// Presence and structural validity confer neither authentication nor authorization.
/// </summary>
public sealed class ActorChain
{
    public const int MaximumDelegatedActors = 32;

    public ActorChain(HumanPrincipal owner, DeviceId device, InstallationId installation,
        SessionId session, InstanceId callerInstance, IEnumerable<DelegatedActor> actors)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(actors);
        _ = device.ToWire();
        _ = installation.ToWire();
        _ = session.ToWire();
        _ = callerInstance.ToWire();
        var entries = new List<DelegatedActor>();
        var identities = new HashSet<(ActorKind, Guid)>();
        foreach (var actor in actors)
        {
            ArgumentNullException.ThrowIfNull(actor);
            if (entries.Count == MaximumDelegatedActors || !identities.Add((actor.Kind, actor.ActorId)))
            {
                throw new ArgumentException("Actor chain is too long or contains a repeated actor.", nameof(actors));
            }

            entries.Add(actor);
        }

        Owner = owner;
        Device = device;
        Installation = installation;
        Session = session;
        CallerInstance = callerInstance;
        Actors = entries.AsReadOnly();
    }

    public HumanPrincipal Owner { get; }
    public DeviceId Device { get; }
    public InstallationId Installation { get; }
    public SessionId Session { get; }
    public InstanceId CallerInstance { get; }
    /// <summary>Delegation order from the human entry point to the final actor; never sorted or collapsed.</summary>
    public ReadOnlyCollection<DelegatedActor> Actors { get; }
}

/// <summary>Explicit operation carrier. The later decision pipeline must still authenticate and authorize.</summary>
public sealed class ActorOperation<T>
{
    public ActorOperation(ActorChain actors, T payload)
    {
        ArgumentNullException.ThrowIfNull(actors);
        Actors = actors;
        Payload = payload;
    }

    public ActorChain Actors { get; }
    public T Payload { get; }

    /// <summary>Carry the identical chain into the next layer without reconstructing identities.</summary>
    public ActorOperation<TNext> Forward<TNext>(TNext payload) => new(Actors, payload);
}
