// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Resources;

/// <summary>A running attempt as the Critical victim choice reads it (<see cref="CriticalShedding.Victim"/>).</summary>
/// <param name="Name">The attempt's name.</param>
/// <param name="Priority">Its priority (unspecified counts as NORMAL).</param>
/// <param name="StartedTimestamp">When it started (monotonic), or <see langword="null"/> while unknown (counted as the most recent).</param>
/// <param name="Preemptible">It may be stopped for pressure.</param>
/// <param name="HasHandle">Its container exists (launched).</param>
/// <param name="Finalizing">Its result is being recorded.</param>
/// <param name="Stopping">It is already being stopped for another reason.</param>
/// <param name="OomKilled">Its own container has recorded an OOM kill (Linux <c>memory.events oom_kill</c>): it is already ending.</param>
public sealed record ShedCandidate(string Name, Priority Priority, long? StartedTimestamp, bool Preemptible, bool HasHandle, bool Finalizing,
    bool Stopping, bool OomKilled);

/// <summary>
/// How many preemptible attempts the Critical level stops (03 sections 5.4 and 7; R-RES-009). The level itself (its 5 s persistence, its
/// journal, finding and notification, and the 10 s OOM hold) is the <see cref="PressureEvaluator"/>'s; this rule only decides, at each
/// evaluation, whether one more attempt must be stopped now:
/// <list type="bullet">
/// <item>A stop is due only while the level in force is Critical and either available memory is below the Critical threshold at this very
/// evaluation (the raw memory condition, not the level held by persistence), or an OOM kill newly observed machine-wide has not been
/// answered by a stop yet. An OOM-kill-only Critical (memory above the threshold) therefore stops at most one attempt per newly observed
/// kill, never one per second of the hold, and the exit persistence of the level never stops anything by itself.</item>
/// <item>After a stop no other is due until that victim has finalized and one more evaluation has passed, so the next decision reads a
/// sample taken after the victim's memory was freed.</item>
/// </list>
/// Pure: the caller supplies each evaluation and whether its last victim still runs; it is used from the monitor's thread only.
/// </summary>
public sealed class CriticalShedding
{
    private bool _awaitingVictim;
    private long _unansweredOomKills;

    /// <summary>True while a stopped victim has not finalized, or finalized after this evaluation's sample was taken.</summary>
    public bool AwaitingVictim => _awaitingVictim;

    /// <summary>OOM kills observed while the raw level is Critical that no stop has answered yet.</summary>
    public long UnansweredOomKills => _unansweredOomKills;

    /// <summary>
    /// Reads one evaluation and returns whether one preemptible attempt must be stopped now; the caller calls <see cref="Stopped"/> when
    /// it stopped one.
    /// </summary>
    /// <param name="level">The level in force.</param>
    /// <param name="raw">The raw level of this evaluation (its condition before persistence).</param>
    /// <param name="memoryCritical">Available memory is below the Critical threshold at this evaluation.</param>
    /// <param name="newOomKills">OOM kills newly observed at this evaluation.</param>
    /// <param name="victimRunning">The last stopped victim is still supervised (not finalized).</param>
    public bool ShouldStop(PressureLevel level, PressureLevel raw, bool memoryCritical, long newOomKills, bool victimRunning)
    {
        // A kill is answered while its hold lasts (the raw level stays Critical for it); once the raw condition clears it is forgotten.
        _unansweredOomKills = raw == PressureLevel.Critical ? _unansweredOomKills + Math.Max(0, newOomKills) : 0;
        if (_awaitingVictim)
        {
            // This evaluation's sample may predate the victim's exit: the next one measures what it freed.
            _awaitingVictim = victimRunning;
            return false;
        }

        return level == PressureLevel.Critical && (memoryCritical || _unansweredOomKills > 0);
    }

    /// <summary>
    /// The attempt to stop: among the preemptible attempts that are launched, not finalizing and not already stopping, the lowest priority
    /// first, the most recently started first within a priority. An attempt whose own container already recorded an OOM kill is skipped:
    /// with <c>OOMPolicy=stop</c> its unit is still ending through its end steps, and stopping it would record PREEMPTED instead of
    /// OOM_KILLED and spend the kill's stop on an attempt that is ending anyway, so the next one is chosen as if it had ended at once.
    /// <see langword="null"/> when none is eligible.
    /// </summary>
    public static ShedCandidate? Victim(IEnumerable<ShedCandidate> candidates)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        return candidates
            .Where(candidate => candidate.Preemptible && candidate.HasHandle && !candidate.Finalizing && !candidate.Stopping && !candidate.OomKilled)
            .OrderByDescending(candidate => candidate.Priority == Priority.Unspecified ? (int)Priority.Normal : (int)candidate.Priority)
            .ThenByDescending(candidate => candidate.StartedTimestamp ?? long.MaxValue)
            .FirstOrDefault();
    }

    /// <summary>Records that one attempt was stopped: it answers one unanswered OOM kill, and no other stop is due until it finalized.</summary>
    public void Stopped()
    {
        _awaitingVictim = true;
        _unansweredOomKills = Math.Max(0, _unansweredOomKills - 1);
    }
}
