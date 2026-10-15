// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.CommandLine;

/// <summary>The CLI's exit codes (experience/cli.md section 3).</summary>
public static class ExitCodes
{
    /// <summary>Success.</summary>
    public const int Success = 0;

    /// <summary>Operation failed (error printed).</summary>
    public const int Failed = 1;

    /// <summary>Usage error (invalid arguments).</summary>
    public const int Usage = 2;

    /// <summary>Node already running (<c>node run</c>).</summary>
    public const int AlreadyRunning = 3;

    /// <summary>Not found (lookups).</summary>
    public const int NotFound = 4;

    /// <summary>Permission denied.</summary>
    public const int PermissionDenied = 5;

    /// <summary>Approval pending (mutations).</summary>
    public const int ApprovalPending = 6;

    /// <summary>Conflict (revision, already exists, digest).</summary>
    public const int Conflict = 7;

    /// <summary>Entitlement required (gated features).</summary>
    public const int EntitlementRequired = 8;

    /// <summary>Node unreachable and nothing was submitted (<c>EX_TEMPFAIL</c>, effect DID_NOT_HAPPEN).</summary>
    public const int NodeUnreachable = 75;

    /// <summary>The exit code of a node error (section 3: by category and code).</summary>
    public static int For(ArcError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return (error.Category, error.Code) switch
        {
            (_, "approval_required") => ApprovalPending,
            (_, "not_found") => NotFound,
            (ErrorCategory.Validation, _) => Usage,
            (ErrorCategory.Authorization, _) or (ErrorCategory.Authentication, _) => PermissionDenied,
            (ErrorCategory.Conflict, _) => Conflict,
            (ErrorCategory.Entitlement, _) => EntitlementRequired,
            _ => Failed,
        };
    }

    /// <summary>The exit code when no ready node could be reached.</summary>
    public static int For(NodeUnavailableException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return exception.Reason switch
        {
            NodeUnavailableReason.AccessDenied => PermissionDenied,
            NodeUnavailableReason.Incompatible => Failed,
            _ => NodeUnreachable,
        };
    }
}
