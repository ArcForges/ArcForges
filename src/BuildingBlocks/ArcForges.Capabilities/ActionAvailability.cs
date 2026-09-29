// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation.Errors;

namespace ArcForges.Capabilities;

/// <summary>The closed availability projection defined by the shared Action contract.</summary>
public enum AvailabilityResult
{
    Available = 0,
    NotApplicableToContext = 1,
    AppNotInstalled = 2,
    AppNotRunning = 3,
    IncompatibleVersion = 4,
    PermissionRequired = 5,
    EntitlementRequired = 6,
    PolicyDisabled = 7,
    TemporarilyUnavailable = 8,
}

/// <summary>Stable identity of a user-facing action; it is distinct from a capability operation key.</summary>
public sealed record ActionKey
{
    public ActionKey(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }

    public string Value { get; }
}

/// <summary>
/// Pure, statically registered projection over the action's bound capabilities and frozen context.
/// Rules must be non-capturing so they cannot retain ambient services or mutable invocation state.
/// </summary>
public delegate AvailabilityResult ActionAvailabilityRule(
    IReadOnlyList<CapabilityRegistration> capabilities,
    FrozenContextSnapshot context);

/// <summary>The availability-relevant static portion of an action descriptor.</summary>
public sealed class ActionDescriptor
{
    private readonly string[] _capabilityKeys;
    private readonly IReadOnlyList<string> _capabilityKeyView;

    public ActionDescriptor(ActionKey key, IEnumerable<string> capabilityKeys, ActionAvailabilityRule availabilityRule)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(capabilityKeys);
        ArgumentNullException.ThrowIfNull(availabilityRule);
        if (availabilityRule.Target is not null)
        {
            throw new ArgumentException("Availability rules must be statically registered non-capturing predicates.", nameof(availabilityRule));
        }

        var suppliedKeys = capabilityKeys.ToArray();
        if (suppliedKeys.Length == 0 || suppliedKeys.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("An action must bind at least one non-empty capability key.", nameof(capabilityKeys));
        }

        if (suppliedKeys.Distinct(StringComparer.Ordinal).Count() != suppliedKeys.Length)
        {
            throw new ArgumentException("An action cannot bind the same capability more than once.", nameof(capabilityKeys));
        }

        Key = key;
        _capabilityKeys = suppliedKeys.OrderBy(item => item, StringComparer.Ordinal).ToArray();
        _capabilityKeyView = Array.AsReadOnly(_capabilityKeys);
        AvailabilityRule = availabilityRule;
    }

    public ActionKey Key { get; }
    public IReadOnlyList<string> CapabilityKeys => _capabilityKeyView;
    public ActionAvailabilityRule AvailabilityRule { get; }
}

/// <summary>Computes action availability from its static capability bindings and one frozen context snapshot.</summary>
public interface ICapabilityProvider
{
    ValueTask<Outcome<AvailabilityResult>> EvaluateAvailabilityAsync(
        ActionKey actionKey,
        FrozenContextSnapshot context,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Per-composition evaluator over a fixed capability registry and action catalogue. It performs no discovery,
/// I/O, or mutable registration while UI code enumerates action availability.
/// </summary>
public sealed class CapabilityAvailabilityProvider : ICapabilityProvider
{
    private readonly Dictionary<ActionKey, RegisteredAction> _actions;

    public CapabilityAvailabilityProvider(CapabilityRegistry capabilities, IEnumerable<ActionDescriptor> actions)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
        ArgumentNullException.ThrowIfNull(actions);

        var registered = new Dictionary<ActionKey, RegisteredAction>();
        foreach (var action in actions)
        {
            ArgumentNullException.ThrowIfNull(action);
            var boundCapabilities = new List<CapabilityRegistration>(action.CapabilityKeys.Count);
            foreach (var key in action.CapabilityKeys)
            {
                var capability = capabilities.Find(key);
                if (capability is null)
                {
                    throw new ArgumentException($"Action '{action.Key.Value}' references an unregistered capability '{key}'.", nameof(actions));
                }

                boundCapabilities.Add(capability);
            }

            var registration = new RegisteredAction(action, Array.AsReadOnly(boundCapabilities.ToArray()));
            if (!registered.TryAdd(action.Key, registration))
            {
                throw new ArgumentException($"Action '{action.Key.Value}' is registered more than once.", nameof(actions));
            }
        }

        _actions = registered;
    }

    ValueTask<Outcome<AvailabilityResult>> ICapabilityProvider.EvaluateAvailabilityAsync(
        ActionKey actionKey,
        FrozenContextSnapshot context,
        CancellationToken cancellationToken)
    {
        if (actionKey is null || context is null)
        {
            return Refuse("validation.invalid_request");
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!_actions.TryGetValue(actionKey, out var registration))
        {
            return Refuse("validation.invalid_request");
        }

        var result = registration.Descriptor.AvailabilityRule(registration.Capabilities, context);
        return Enum.IsDefined(result)
            ? ValueTask.FromResult(Outcome.Success(result))
            : Refuse("internal.unexpected");
    }

    private static ValueTask<Outcome<AvailabilityResult>> Refuse(string code) =>
        ValueTask.FromResult(Outcome.Failure<AvailabilityResult>(TypedFailure.Create(code)));

    private sealed record RegisteredAction(
        ActionDescriptor Descriptor,
        IReadOnlyList<CapabilityRegistration> Capabilities);
}
