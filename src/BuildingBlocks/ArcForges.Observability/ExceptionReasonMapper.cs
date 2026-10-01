// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using System.Text.Json;
using ArcForges.Foundation.Errors;

namespace ArcForges.Observability;

/// <summary>
/// Maps an exception to a registered reason code before anything is exported (observability architecture RD-07). The
/// mapping looks only at the exception's runtime type: its message, data, stack trace and inner messages can embed
/// user input and are never read. An exception type the mapper has no rule for is the generic
/// <c>internal.unexpected</c> reason, never text.
/// </summary>
public sealed class ExceptionReasonMapper
{
    private const int MaximumUnwrapDepth = 8;

    private static readonly (Type Type, string Code)[] BuiltIn =
    [
        (typeof(TimeoutException), "dependency.timeout"),
        (typeof(UnauthorizedAccessException), "perm.resource_denied"),
        (typeof(FileNotFoundException), "state.not_found"),
        (typeof(DirectoryNotFoundException), "state.not_found"),
        (typeof(KeyNotFoundException), "state.not_found"),
        (typeof(IOException), "resource.unavailable"),
        (typeof(ArgumentException), "validation.invalid_request"),
        (typeof(FormatException), "validation.invalid_request"),
        (typeof(JsonException), "validation.invalid_request"),
        (typeof(InvalidOperationException), "state.invalid_transition"),
    ];

    private readonly (Type Type, ReasonCode Reason)[] _additional;

    /// <summary>The mapper that uses only the built-in rules.</summary>
    public static ExceptionReasonMapper Default { get; } = new(null);

    /// <summary>
    /// Adds owner-specific rules. They are consulted first, in the order given, so list the most specific type first.
    /// Each key must be an exception type and each value a registered <see cref="ReasonCode"/>.
    /// </summary>
    public ExceptionReasonMapper(IEnumerable<KeyValuePair<Type, ReasonCode>>? additional)
    {
        var rules = new List<(Type, ReasonCode)>();
        foreach (KeyValuePair<Type, ReasonCode> rule in additional ?? [])
        {
            ArgumentNullException.ThrowIfNull(rule.Key);
            ArgumentNullException.ThrowIfNull(rule.Value);
            if (!typeof(Exception).IsAssignableFrom(rule.Key))
            {
                throw new ArgumentException("A reason rule must be keyed by an exception type.", nameof(additional));
            }

            if (!ReasonCodes.TryGet(rule.Value.Code, out ReasonCode? registered) || !ReferenceEquals(registered, rule.Value))
            {
                throw new ArgumentException("A reason rule must name a registered reason code.", nameof(additional));
            }

            rules.Add((rule.Key, rule.Value));
        }

        _additional = rules.ToArray();
    }

    /// <summary>
    /// Returns the reason code for the exception, or null when the exception is a cancellation, which is an outcome
    /// rather than a failure. A wrapper that holds exactly one exception reports that exception's reason.
    /// </summary>
    public ReasonCode? Map(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        Exception current = exception;
        for (int depth = 0; depth < MaximumUnwrapDepth; depth++)
        {
            if (current is OperationCanceledException)
            {
                return null;
            }

            foreach ((Type type, ReasonCode reason) in _additional)
            {
                if (type.IsInstanceOfType(current))
                {
                    return reason;
                }
            }

            Exception? inner = SingleWrapped(current);
            if (inner is null)
            {
                break;
            }

            current = inner;
        }

        foreach ((Type type, string code) in BuiltIn)
        {
            if (type.IsInstanceOfType(current))
            {
                return ReasonCodes.Get(code);
            }
        }

        return ReasonCodes.Get("internal.unexpected");
    }

    private static Exception? SingleWrapped(Exception exception) => exception switch
    {
        AggregateException aggregate => aggregate.Flatten().InnerExceptions is { Count: 1 } inner ? inner[0] : null,
        TargetInvocationException { InnerException: { } inner } => inner,
        _ => null,
    };
}
