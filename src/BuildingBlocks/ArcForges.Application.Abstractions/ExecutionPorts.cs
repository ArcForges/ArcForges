// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Foundation.Execution;

namespace ArcForges.Application.Abstractions;

/// <summary>Storage-free per-execution ports supplied explicitly by the owning application.</summary>
public interface IExecutionContext
{
    ExecutionIdentity Identity { get; }
    IClock Clock { get; }
    CancellationToken Cancellation { get; }
}

/// <summary>Lifecycle cancellation does not assert that an already dispatched effect did not happen.</summary>
public interface IApplicationLifecycle
{
    CancellationToken Stopping { get; }
    ValueTask<Outcome<bool>> RequestStopAsync(CancellationToken cancellationToken);
}
