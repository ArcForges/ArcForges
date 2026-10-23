// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Resources;

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

    /// <summary>Records that one attempt was stopped: it answers one unanswered OOM kill, and no other stop is due until it finalized.</summary>
    public void Stopped()
    {
        _awaitingVictim = true;
        _unansweredOomKills = Math.Max(0, _unansweredOomKills - 1);
    }
}
