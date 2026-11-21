// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Platform;

/// <summary>
/// A command could not be prepared for execution: a catalogued <c>VALIDATION</c> code (errors.md) with the detail the error carries in
/// <c>details.state.reason</c>: <c>program_not_found</c> (the program), <c>unsafe_batch_argument</c> (the argument index),
/// <c>unsupported_shell</c> (the shell kind) or <c>invalid_argument</c> (the field and rule).
/// </summary>
public sealed class CommandRefusedException : Exception
{
    /// <summary>Creates the exception.</summary>
    public CommandRefusedException(string code, string reason)
        : base($"{code}: {reason}")
    {
        Code = code;
        Reason = reason;
    }

    /// <summary>Creates the exception.</summary>
    public CommandRefusedException()
        : this("invalid_argument", string.Empty)
    {
    }

    /// <summary>Creates the exception.</summary>
    public CommandRefusedException(string message)
        : this("invalid_argument", message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public CommandRefusedException(string message, Exception innerException)
        : base(message, innerException)
    {
        Code = "invalid_argument";
        Reason = message;
    }

    /// <summary>The catalogued VALIDATION code.</summary>
    public string Code { get; } = "invalid_argument";

    /// <summary><c>details.state.reason</c>.</summary>
    public string Reason { get; } = string.Empty;
}
