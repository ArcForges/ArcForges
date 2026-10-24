// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.RegularExpressions;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;

namespace ArcForges.Node.Core.Scheduling;

/// <summary>A stored policy revision (node-store.md <c>policy_document</c>).</summary>
/// <param name="Revision">The revision number (1 is the default document written at store creation).</param>
/// <param name="Document">The document.</param>
/// <param name="Digest">SHA-256 of the canonical binary document.</param>
/// <param name="CreatedAt">When it was written (microseconds).</param>
/// <param name="Actor">Who wrote it.</param>
/// <param name="Comment">Its comment.</param>
public sealed record PolicyRow(long Revision, PolicyDocument Document, byte[] Digest, long CreatedAt, ActorRef Actor, string? Comment);

/// <summary>
/// The validation of a <see cref="PolicyDocument"/> (policy.proto <c>validate:</c> comments; <c>PolicyService.ValidatePolicy</c>): each
/// broken rule is an ERROR issue with the field path; questionable but allowed values are WARNING issues. A document with an ERROR issue
/// is never applied (<c>VALIDATION/invalid_policy</c>).
/// </summary>
public static class PolicyRules
{
    private const ulong GiB = 1024UL * 1024 * 1024;

    /// <summary>The longest regular expression the policy accepts (heavy patterns: 512 characters).</summary>
    public const int MaxPatternLength = 512;

    /// <summary>The policy revisions kept (node-store.md <c>policy_document</c>: the last 200).</summary>
    public const int KeptRevisions = 200;

    /// <summary>The pool name rule (queue.proto <c>CreatePool.name</c>).</summary>
    public static readonly Regex PoolName = new("^[a-z][a-z0-9-]{0,31}$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>Validates <paramref name="document"/> against the rules; <paramref name="capacityMemory"/> and <paramref name="logicalProcessors"/> are the node's.</summary>
    public static List<PolicyIssue> Validate(PolicyDocument document, long capacityMemory, int logicalProcessors)
    {
        ArgumentNullException.ThrowIfNull(document);
        var issues = new List<PolicyIssue>();
        void Error(string path, string message) => issues.Add(new PolicyIssue { Path = path, Severity = Severity.Error, Message = message });
        void Warn(string path, string message) => issues.Add(new PolicyIssue { Path = path, Severity = Severity.Warning, Message = message });

        var resources = document.Resources ?? new ResourcePolicy();
        if (resources.HasReserveCpuFixedMillicores && resources.ReserveCpuFixedMillicores > 64_000)
        {
            Error("resources.reserve_cpu_fixed_millicores", "0..64,000");
        }

        Fraction(resources.HasReserveCpuFraction, resources.ReserveCpuFraction, 0, 0.9, "resources.reserve_cpu_fraction", Error);
        Fraction(resources.HasReserveMemFraction, resources.ReserveMemFraction, 0, 0.9, "resources.reserve_mem_fraction", Error);
        if (resources.HasMinManagedCpuMillicores && resources.MinManagedCpuMillicores < 100)
        {
            Error("resources.min_managed_cpu_millicores", ">= 100");
        }

        Fraction(resources.HasOvercommitCpu, resources.OvercommitCpu, 1.0, 4.0, "resources.overcommit_cpu", Error);
        if (resources.HasOvercommitMem && resources.OvercommitMem != 1.0)
        {
            Error("resources.overcommit_mem", "fixed 1.0 (memory is never overcommitted at admission)");
        }

        Fraction(resources.HasSmoothingAlphaUp, resources.SmoothingAlphaUp, 0.05, 1, "resources.smoothing_alpha_up", Error);
        Fraction(resources.HasSmoothingAlphaDown, resources.SmoothingAlphaDown, 0.01, 1, "resources.smoothing_alpha_down", Error);
        if (resources.HasStarvationBoundMs && resources.StarvationBoundMs < 60_000)
        {
            Error("resources.starvation_bound_ms", ">= 60 s");
        }

        if (resources.HasLargeTaskBypassMs && resources.LargeTaskBypassMs < 10_000)
        {
            Error("resources.large_task_bypass_ms", ">= 10 s");
        }

        if (resources.HasLargeTaskReservationMaxMs && resources.LargeTaskReservationMaxMs < 60_000)
        {
            Error("resources.large_task_reservation_max_ms", ">= 60 s");
        }

        Fraction(resources.HasCommitFactor, resources.CommitFactor, 1.0, 4.0, "resources.commit_factor", Error);
        Fraction(resources.HasGuestStandaloneFraction, resources.GuestStandaloneFraction, 0.05, 0.5, "resources.guest_standalone_fraction", Error);
        var reserveMem = (long)((resources.HasReserveMemFixedBytes ? resources.ReserveMemFixedBytes : 2 * GiB)
            + ((resources.HasReserveMemFraction ? resources.ReserveMemFraction : 0.10) * capacityMemory));
        if (reserveMem >= capacityMemory)
        {
            Warn("resources.reserve_mem_fixed_bytes", "the memory reserve is at least the machine's memory: no managed task can run");
        }

        if (resources.HasMaxTaskMemoryBytes && (long)resources.MaxTaskMemoryBytes > capacityMemory - reserveMem)
        {
            Warn("resources.max_task_memory_bytes", "larger than the managed share C_mem - R_mem; larger requests are still exceeds_capacity");
        }

        if (resources.Pressure is { } pressure)
        {
            Fraction(pressure.HasTightAvailableFraction, pressure.TightAvailableFraction, 0.001, 0.999, "resources.pressure.tight_available_fraction", Error);
            Fraction(pressure.HasPressureAvailableFraction, pressure.PressureAvailableFraction, 0.001, 0.999, "resources.pressure.pressure_available_fraction", Error);
            Fraction(pressure.HasCriticalAvailableFraction, pressure.CriticalAvailableFraction, 0.001, 0.999, "resources.pressure.critical_available_fraction", Error);
            var tight = pressure.HasTightAvailableFraction ? pressure.TightAvailableFraction : 0.10;
            var high = pressure.HasPressureAvailableFraction ? pressure.PressureAvailableFraction : 0.05;
            var critical = pressure.HasCriticalAvailableFraction ? pressure.CriticalAvailableFraction : 0.02;
            if (!(tight > high && high > critical))
            {
                Error("resources.pressure", "tight > pressure > critical available fractions");
            }

            if (pressure.HasMemoryPsiSomeAvg10 && pressure.MemoryPsiSomeAvg10 is < 0 or > 100)
            {
                Error("resources.pressure.memory_psi_some_avg10", "0..100");
            }
        }

        // Pools: unique names, the built-in pools present, weights and parallelism.
        var names = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < document.Pools.Count; index++)
        {
            var pool = document.Pools[index];
            var path = string.Create(CultureInfo.InvariantCulture, $"pools[{index}]");
            if (!pool.HasName || !PoolName.IsMatch(pool.Name))
            {
                Error(path + ".name", "^[a-z][a-z0-9-]{0,31}$");
            }
            else if (!names.Add(pool.Name))
            {
                Error(path + ".name", $"'{pool.Name}' is listed twice");
            }

            if (pool.HasWeight && pool.Weight is < 1 or > 100)
            {
                Error(path + ".weight", "1..100");
            }

            Parallelism(pool.HasMaxParallelMode, pool.MaxParallelMode, pool.HasMaxParallelFixed, pool.MaxParallelFixed, path + ".max_parallel", Error);
            if (pool.HasDefaultPriority && (pool.DefaultPriority is Priority.Interactive or Priority.Unspecified || !Enum.IsDefined(pool.DefaultPriority)))
            {
                Error(path + ".default_priority", "HIGH, NORMAL, LOW or BACKGROUND (not INTERACTIVE)");
            }
        }

        if (document.Pools.Count > 0)
        {
            foreach (var builtIn in DefaultPolicy.BuiltInPools.Where(builtIn => !names.Contains(builtIn)))
            {
                Error("pools", $"the built-in pool '{builtIn}' cannot be removed");
            }
        }

        for (var index = 0; index < document.Parallelism.Count; index++)
        {
            var rule = document.Parallelism[index];
            var path = string.Create(CultureInfo.InvariantCulture, $"parallelism[{index}]");
            if (!rule.HasScope || rule.Scope == ParallelismScope.Unspecified || !Enum.IsDefined(rule.Scope))
            {
                Error(path + ".scope", "GLOBAL, POOL, WORKSPACE or SESSION");
                continue;
            }

            if (rule.Scope == ParallelismScope.Global ? rule.HasTarget && rule.Target.Length > 0 : !rule.HasTarget || rule.Target.Length == 0)
            {
                Error(path + ".target", rule.Scope == ParallelismScope.Global ? "empty for GLOBAL" : "required");
            }
            else if (rule.Scope == ParallelismScope.Pool && !names.Contains(rule.Target) && !(document.Pools.Count == 0 && DefaultPolicy.BuiltInPools.Contains(rule.Target)))
            {
                Error(path + ".target", $"'{rule.Target}' is not a pool");
            }
            else if (rule.Scope is ParallelismScope.Workspace or ParallelismScope.Session && !IdText.TryParse(rule.Target, out _))
            {
                Error(path + ".target", "an ID (base32)");
            }

            if (!rule.HasMode || rule.Mode == ParallelismMode.Unspecified)
            {
                Error(path + ".mode", "required");
            }

            Parallelism(rule.HasMode, rule.Mode, rule.HasFixed, rule.Fixed, path, Error);
        }

        // Retry safety (AD-0006 section 4): rules assert PURE or IDEMPOTENT for a command pattern.
        if (document.RetrySafety is { } safety)
        {
            for (var index = 0; index < safety.Rules.Count; index++)
            {
                var rule = safety.Rules[index];
                var path = string.Create(CultureInfo.InvariantCulture, $"retry_safety.rules[{index}]");
                Pattern(rule.HasPattern ? rule.Pattern : null, path + ".pattern", required: true, Error);
                if (rule.SideEffect is not (SideEffectClass.Pure or SideEffectClass.Idempotent))
                {
                    Error(path + ".side_effect", "PURE or IDEMPOTENT");
                }

                if (rule.WorkspaceId is { Value.Length: > 0 and not 16 })
                {
                    Error(path + ".workspace_id", "a 16-byte ID or empty");
                }
            }
        }

        if (document.Agents is { } agents)
        {
            if (agents.AllowedCommandPatterns.Count > 256)
            {
                Error("agents.allowed_command_patterns", "<= 256 patterns");
            }

            for (var index = 0; index < agents.AllowedCommandPatterns.Count; index++)
            {
                Pattern(agents.AllowedCommandPatterns[index], string.Create(CultureInfo.InvariantCulture, $"agents.allowed_command_patterns[{index}]"), required: true, Error);
            }

            if (agents.HasDefaultPool && document.Pools.Count > 0 && !names.Contains(agents.DefaultPool))
            {
                Error("agents.default_pool", $"'{agents.DefaultPool}' is not a pool");
            }
        }

        if (document.Routing is { } routing)
        {
            for (var index = 0; index < routing.HeavyPatterns.Count; index++)
            {
                Pattern(routing.HeavyPatterns[index].HasPattern ? routing.HeavyPatterns[index].Pattern : null,
                    string.Create(CultureInfo.InvariantCulture, $"routing.heavy_patterns[{index}].pattern"), required: true, Error);
            }

            for (var index = 0; index < routing.PassthroughPatterns.Count; index++)
            {
                Pattern(routing.PassthroughPatterns[index], string.Create(CultureInfo.InvariantCulture, $"routing.passthrough_patterns[{index}]"), required: true, Error);
            }

            if (routing.HasLightCpuMillicores && routing.LightCpuMillicores is < 1 or > 1_024_000)
            {
                Error("routing.light_cpu_millicores", "1..1,024,000");
            }

            if (routing.HasLightMemBytes && routing.LightMemBytes < 1024 * 1024)
            {
                Error("routing.light_mem_bytes", ">= 1 MiB");
            }
        }

        if (document.Storage is { } storage && storage.HasGuardTakeoverMs && storage.GuardTakeoverMs is < 2000 or > 60_000)
        {
            Error("storage.guard_takeover_ms", "2000..60000");
        }

        if (document.Caches is { } caches)
        {
            if (caches.DotnetSharedBuildServers)
            {
                Error("caches.dotnet_shared_build_servers", "reserved (roadmap RM-13): refused in release 1");
            }

            if (caches.HasSccachePortFirst || caches.HasSccachePortLast)
            {
                var first = caches.HasSccachePortFirst ? caches.SccachePortFirst : 0;
                var last = caches.HasSccachePortLast ? caches.SccachePortLast : first + 399;
                var globalMax = resources.HasGlobalMaxRunning && resources.GlobalMaxRunning > 0 ? resources.GlobalMaxRunning : (uint)Math.Min(64, 2 * logicalProcessors);
                if (first < 1024 || last > 65_535 || first >= last || last - first + 1 < 64 || last - first + 1 <= globalMax)
                {
                    Error("caches.sccache_port_first", "1024 <= first < last <= 65535, at least 64 ports and more ports than the effective global_max_running");
                }
            }
        }

        if (document.ResultCache is { } resultCache && (resultCache.DefaultMode == ResultCacheMode.Restore || resultCache.WorkspaceModes.Values.Any(mode => mode == ResultCacheMode.Restore)))
        {
            Error("result_cache", "RESTORE is roadmap RM-04: refused in release 1");
        }

        if (document.Lan is { } lan && lan.HasPort && lan.Port is < 1 or > 65_535)
        {
            Error("lan.port", "1..65535");
        }

        if (document.Updates is { } updates)
        {
            if (updates.HasChannel && updates.Channel is not ("stable" or "beta" or "dev"))
            {
                Error("updates.channel", "stable, beta or dev");
            }

            for (var index = 0; index < updates.Windows.Count; index++)
            {
                var window = updates.Windows[index];
                if (window.DaysMask > 127 || window.StartMinute > 1439 || window.EndMinute is < 1 or > 1440)
                {
                    Error(string.Create(CultureInfo.InvariantCulture, $"updates.windows[{index}]"), "days_mask <= 127, start_minute 0..1439, end_minute 1..1440");
                }
            }
        }

        for (var index = 0; index < document.Permissions.Count; index++)
        {
            // 11 section 1: overrides of the permission matrix (the operation a non-fixed matrix row; SCRIPT, AGENT or REMOTE).
            if (Security.PermissionMatrix.Valid(document.Permissions[index]) is { } why)
            {
                Error(string.Create(CultureInfo.InvariantCulture, $"permissions[{index}]"), why);
            }
        }

        if (document.Privacy is { } privacy && privacy.SecretNamePatterns.Any(pattern => pattern.Length == 0))
        {
            Error("privacy.secret_name_patterns", "patterns are non-empty");
        }

        return issues;
    }

    /// <summary>
    /// The side-effect class a <c>retry_safety</c> rule asserts for a command (AD-0006 section 4: <c>SideEffectSource.POLICY</c>), or
    /// <see langword="null"/>: the first rule whose pattern matches the command line and whose workspace is empty or the task's.
    /// </summary>
    public static SideEffectClass? RetrySafety(IReadOnlyList<RetrySafetyRule> rules, string commandLine, ReadOnlySpan<byte> workspace)
    {
        ArgumentNullException.ThrowIfNull(rules);
        foreach (var rule in rules)
        {
            if (rule.WorkspaceId is { Value.Length: 16 } scope && !scope.Value.Span.SequenceEqual(workspace))
            {
                continue;
            }

            if (rule.SideEffect is not (SideEffectClass.Pure or SideEffectClass.Idempotent) || !rule.HasPattern)
            {
                continue;
            }

            try
            {
                if (new Regex(rule.Pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant).IsMatch(commandLine))
                {
                    return rule.SideEffect;
                }
            }
            catch (ArgumentException)
            {
                // A pattern validation refuses; an older stored one that no longer parses simply never matches.
            }
        }

        return null;
    }

    /// <summary>A revision row as <c>PolicyRevision</c>.</summary>
    public static PolicyRevision Revision(PolicyRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        var revision = new PolicyRevision
        {
            Revision = new Revision { Value = row.Revision },
            CreatedAt = Notifications.Time(row.CreatedAt),
            Actor = row.Actor,
            Digest = Convert.ToHexStringLower(row.Digest),
        };
        if (row.Comment is { } comment)
        {
            revision.Comment = comment;
        }

        return revision;
    }

    /// <summary>
    /// Writes a new current revision with <paramref name="document"/> (the policy engine; node-store.md <c>policy_document</c>: exactly one
    /// current revision, the last 200 kept) and returns it.
    /// </summary>
    public static PolicyRow Write(StoreTransaction transaction, PolicyDocument document, ActorRef actor, string? comment)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(actor);
        var next = Convert.ToInt64(transaction.Scalar("SELECT coalesce(max(revision), 0) + 1 FROM policy_document;"), CultureInfo.InvariantCulture);
        transaction.Execute("UPDATE policy_document SET is_current = 0 WHERE is_current = 1;");
        transaction.Execute(
            """
            INSERT INTO policy_document (revision, document, digest, created_at, actor, comment, approval_id, is_current)
            VALUES ($revision, $document, $digest, $now, $actor, $comment, NULL, 1);
            """,
            ("$revision", next), ("$document", document.ToByteArray()), ("$digest", PolicyDocuments.Digest(document)), ("$now", transaction.NowMicroseconds),
            ("$actor", actor.ToByteArray()), ("$comment", comment));
        transaction.Execute("DELETE FROM policy_document WHERE is_current = 0 AND revision <= $oldest;", ("$oldest", next - KeptRevisions));
        return Get(transaction, next)!;
    }

    /// <summary>The current revision.</summary>
    public static PolicyRow Current(StoreReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        return Read(reader, "WHERE is_current = 1", null, 1).Single();
    }

    /// <summary>A stored revision, or <see langword="null"/>.</summary>
    public static PolicyRow? Get(StoreReader reader, long revision)
    {
        ArgumentNullException.ThrowIfNull(reader);
        return Read(reader, "WHERE revision = $value", revision, 1).FirstOrDefault();
    }

    /// <summary>Revisions below <paramref name="before"/>, newest first.</summary>
    public static List<PolicyRow> List(StoreReader reader, long before, int limit)
    {
        ArgumentNullException.ThrowIfNull(reader);
        return Read(reader, "WHERE revision < $value", before, limit);
    }

    private static List<PolicyRow> Read(StoreReader reader, string where, long? value, int limit)
    {
        using var command = reader.CreateCommand(
            $"SELECT revision, document, digest, created_at, actor, comment FROM policy_document {where} ORDER BY revision DESC LIMIT $limit;");
        if (value is { } parameter)
        {
            command.Parameters.AddWithValue("$value", parameter);
        }

        command.Parameters.AddWithValue("$limit", limit);
        using var rows = command.ExecuteReader();
        var result = new List<PolicyRow>();
        while (rows.Read())
        {
            result.Add(new PolicyRow(rows.GetInt64(0), PolicyDocument.Parser.ParseFrom((byte[])rows.GetValue(1)), (byte[])rows.GetValue(2), rows.GetInt64(3),
                ActorRef.Parser.ParseFrom((byte[])rows.GetValue(4)), rows.IsDBNull(5) ? null : rows.GetString(5)));
        }

        return result;
    }
    private static void Fraction(bool present, double value, double low, double high, string path, Action<string, string> error)
    {
        if (present && (double.IsNaN(value) || value < low || value > high))
        {
            error(path, string.Create(CultureInfo.InvariantCulture, $"{low}..{high}"));
        }
    }

    private static void Parallelism(bool hasMode, ParallelismMode mode, bool hasFixed, uint fixedLimit, string path, Action<string, string> error)
    {
        if (hasMode && !Enum.IsDefined(mode))
        {
            error(path + "_mode", "AUTO, FIXED or DISABLED");
        }

        if (mode == ParallelismMode.Fixed && (!hasFixed || fixedLimit is < 1 or > 256))
        {
            error(path + "_fixed", "1..256 with FIXED");
        }
        else if (mode != ParallelismMode.Fixed && hasFixed && fixedLimit > 0)
        {
            error(path + "_fixed", "FIXED only");
        }
    }

    private static void Pattern(string? pattern, string path, bool required, Action<string, string> error)
    {
        if (string.IsNullOrEmpty(pattern))
        {
            if (required)
            {
                error(path, "required");
            }

            return;
        }

        if (pattern.Length > MaxPatternLength)
        {
            error(path, "<= 512 characters");
            return;
        }

        try
        {
            // The RE2-compatible subset: the non-backtracking engine refuses backreferences, lookarounds and atomic groups.
            _ = new Regex(pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            error(path, "an RE2-compatible regular expression (" + NodeLog.OneLine(exception.Message) + ")");
        }
    }
}
