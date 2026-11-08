// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Api;

/// <summary>Refuses environment values that cannot safely transit the center before a relay nonce or transport is acquired.</summary>
internal static class RoutedEnvironmentGuard
{
    /// <summary>
    /// Classifies names in the original bounded wire request, not a re-encoded or last-value-wins message. The policy reader is the current
    /// local policy in production; a failure is a refusal, never an implicit fallback to defaults. Values are never logged or used to classify names.
    /// </summary>
    internal static ArcError? Check(ByteString request, bool ownNode, Id? correlation, TimeProvider clock, Func<IReadOnlyList<string>> readPolicy)
    {
        var names = new List<string>();
        try
        {
            if (!ReadSubmit(new CodedInputStream(request.ToByteArray()), names))
            {
                return Invalid(correlation, clock, "environment cannot be classified safely for the center; no values were sent");
            }
        }
        catch (InvalidProtocolBufferException)
        {
            return Invalid(correlation, clock, "environment cannot be classified safely for the center; no values were sent");
        }

        if (names.Count == 0)
        {
            return null;
        }

        if (!ownNode)
        {
            return Invalid(correlation, clock, "environment values cannot be sent through the center when the target policy is unknown; use node or none inheritance without --env");
        }

        SecretNameMatcher configured;
        try
        {
            configured = new SecretNameMatcher(readPolicy());
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            var error = NodeErrors.InvalidState("environment", "the local policy is unavailable; environment values cannot be classified safely for the center");
            error.CorrelationId = Correlation(correlation, clock);
            return error;
        }

        if (names.Any(name => SecretNameMatcher.Default.IsSecret(name) || configured.IsSecret(name)))
        {
            return Invalid(correlation, clock, "environment secret values cannot be sent through the center; use target node inheritance or --local");
        }

        return null;
    }

    private static ArcError Invalid(Id? correlation, TimeProvider clock, string reason)
    {
        var error = NodeErrors.InvalidArgument(reason);
        error.CorrelationId = Correlation(correlation, clock);
        error.Details.State.State = "environment";
        return error;
    }

    private static Id Correlation(Id? correlation, TimeProvider clock) =>
        Validation.RequiredId(correlation, "correlation_id") is null ? correlation!.Clone() : CommandIds.New(clock);

    // These four fixed message levels are bounded by the existing 253952-byte SubmitNodeTask payload limit. Unknown environment or map-entry
    // fields are unclassifiable. All environment occurrences are inspected, including duplicate map keys a parsed message would collapse.
    // Unrelated fields are skipped unchanged; the reader never recursively descends into command arguments or unrelated messages.
    private static bool ReadSubmit(CodedInputStream input, List<string> names)
    {
        var sawSpec = false;
        uint tag;
        while ((tag = input.ReadTag()) != 0)
        {
            if (tag == 82) // TaskServiceSubmitTaskRequest.spec = 10
            {
                sawSpec = true;
                if (!ReadSpec(new CodedInputStream(input.ReadBytes().ToByteArray()), names))
                {
                    return false;
                }
            }
            else
            {
                input.SkipLastField();
            }
        }

        return sawSpec;
    }

    private static bool ReadSpec(CodedInputStream input, List<string> names)
    {
        uint tag;
        while ((tag = input.ReadTag()) != 0)
        {
            if (tag == 26) // TaskSpec.environment = 3
            {
                if (!ReadEnvironment(new CodedInputStream(input.ReadBytes().ToByteArray()), names))
                {
                    return false;
                }
            }
            else
            {
                input.SkipLastField();
            }
        }

        return true;
    }

    private static bool ReadEnvironment(CodedInputStream input, List<string> names)
    {
        uint tag;
        while ((tag = input.ReadTag()) != 0)
        {
            switch (tag)
            {
                case 8: // inherit
                    if ((EnvironmentInherit)input.ReadEnum() is not (EnvironmentInherit.Caller or EnvironmentInherit.Node or EnvironmentInherit.None))
                    {
                        return false;
                    }
                    break;
                case 18: // set
                case 34: // caller_environment, even when inherit is not CALLER
                    if (!ReadEntry(new CodedInputStream(input.ReadBytes().ToByteArray()), names))
                    {
                        return false;
                    }
                    break;
                case 26: // unset names contain no values
                    input.SkipLastField();
                    break;
                default:
                    return false;
            }
        }

        return true;
    }

    private static bool ReadEntry(CodedInputStream input, List<string> names)
    {
        var sawName = false;
        uint tag;
        while ((tag = input.ReadTag()) != 0)
        {
            if (tag == 10)
            {
                var name = input.ReadString();
                if (name.Length == 0 || name.Contains('=', StringComparison.Ordinal) || name.Contains('\0', StringComparison.Ordinal))
                {
                    return false;
                }

                sawName = true;
                names.Add(name);
            }
            else if (tag == 18) // value: skip without reading or storing it
            {
                input.SkipLastField();
            }
            else
            {
                return false;
            }
        }

        return sawName;
    }
}
