// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Errors;

namespace ArcForges.Security.Approvals;

/// <summary>A user direction update for an already-running command, never an approval or permission grant.</summary>
public sealed class SteeringRequest
{
    public SteeringRequest(Guid steeringId, CommandId runningCommand, HumanPrincipal requestedBy, string direction)
    {
        if (steeringId == Guid.Empty)
        {
            throw new ArgumentException("A nonempty steering identity is required.", nameof(steeringId));
        }

        _ = runningCommand.ToWire();
        ArgumentNullException.ThrowIfNull(requestedBy);
        SecurityText.Validate(direction, 4096, nameof(direction));
        SteeringId = steeringId;
        RunningCommand = runningCommand;
        RequestedBy = requestedBy;
        Direction = direction;
    }

    public Guid SteeringId { get; }
    public CommandId RunningCommand { get; }
    public HumanPrincipal RequestedBy { get; }
    public string Direction { get; }
}

/// <summary>
/// Owner adapter for a running operation. It may update execution direction only; it must not
/// create/alter approvals, grants, capability scope, or the operation's authorized effect.
/// </summary>
public interface IRunningOperationSteerer
{
    ValueTask<bool> TryApplyAsync(SteeringRequest request, CancellationToken cancellationToken = default);
}

/// <summary>Routes steering independently of the approval and step-up mechanisms.</summary>
public sealed class SteeringCoordinator
{
    private readonly IRunningOperationSteerer _steerer;

    public SteeringCoordinator(IRunningOperationSteerer steerer)
    {
        ArgumentNullException.ThrowIfNull(steerer);
        _steerer = steerer;
    }

    public async ValueTask<Outcome<bool>> ApplyAsync(SteeringRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Outcome.Success(await _steerer.TryApplyAsync(request, cancellationToken).ConfigureAwait(false));
    }
}
