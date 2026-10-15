// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;

namespace ArcForges.Supervisor;

/// <summary>
/// Runs the node and restarts it after a crash (architecture 02 section 2 Crash; AD-0003 section 1):
/// <list type="bullet">
/// <item>The node is <c>arcforges.exe node run</c>, started with <c>CREATE_NO_WINDOW</c>, so logon shows no console window.</item>
/// <item>Exit 0 (a requested stop) or 3 (another node already runs) ends the supervisor; exit 75 (an update restart) restarts at once.</item>
/// <item>Any other exit is a crash: the node is restarted after 2 s, 5 s, then 10 s; after 5 crashes within 10 minutes the
/// supervisor records <c>node_crash_loop</c> in its log and exits, so the next client auto-start tries again.</item>
/// </list>
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class NodeSupervisor
{
    /// <summary>The crash-loop window.</summary>
    public static readonly TimeSpan CrashWindow = TimeSpan.FromMinutes(10);

    /// <summary>Crashes within <see cref="CrashWindow"/> that stop the restarts.</summary>
    public const int CrashLimit = 5;

    private const int NodeAlreadyRunning = 3;
    private const int NodeUpdateRestart = 75;

    private readonly SupervisorLocations _locations;
    private readonly TimeProvider _clock;
    private readonly SupervisorLog _log;

    public NodeSupervisor(SupervisorLocations locations, TimeProvider clock)
    {
        _locations = locations;
        _clock = clock;
        _log = new SupervisorLog(locations.LogFile, clock);
    }

    /// <summary>The restart delay after the <paramref name="crashes"/>-th crash within the window (1 is the first).</summary>
    public static TimeSpan Backoff(int crashes) => crashes switch
    {
        <= 1 => TimeSpan.FromSeconds(2),
        2 => TimeSpan.FromSeconds(5),
        _ => TimeSpan.FromSeconds(10),
    };

    public int Run()
    {
        using var instance = new Mutex(initiallyOwned: true, _locations.MutexName, out var created);
        if (!created)
        {
            try
            {
                if (!instance.WaitOne(0))
                {
                    _log.Write("supervisor.already_running");
                    return 0;
                }
            }
            catch (AbandonedMutexException)
            {
                // The previous supervisor ended without releasing it; this one takes over.
            }
        }

        _log.Write("supervisor.started", ("pid", Environment.ProcessId.ToString(CultureInfo.InvariantCulture)), ("testMode", _locations.TestMode ? "true" : "false"));
        if (!File.Exists(_locations.NodeExecutable))
        {
            _log.Write("supervisor.node_missing", ("path", _locations.NodeExecutable));
            return 1;
        }

        var crashes = new Queue<DateTimeOffset>();
        while (true)
        {
            var exit = RunNodeOnce();
            switch (exit)
            {
                case 0:
                    _log.Write("node.stopped");
                    return 0;
                case NodeAlreadyRunning:
                    _log.Write("node.already_running");
                    return 0;
                case NodeUpdateRestart:
                    _log.Write("node.update_restart");
                    continue;
            }

            var now = _clock.GetUtcNow();
            crashes.Enqueue(now);
            while (crashes.Count > 0 && now - crashes.Peek() > CrashWindow)
            {
                crashes.Dequeue();
            }

            if (crashes.Count >= CrashLimit)
            {
                _log.Write("node_crash_loop", ("crashes", crashes.Count.ToString(CultureInfo.InvariantCulture)),
                    ("windowMinutes", CrashWindow.TotalMinutes.ToString(CultureInfo.InvariantCulture)), ("lastExitCode", exit.ToString(CultureInfo.InvariantCulture)));
                return 1;
            }

            var delay = Backoff(crashes.Count);
            _log.Write("node.crashed", ("exitCode", exit.ToString(CultureInfo.InvariantCulture)), ("crashes", crashes.Count.ToString(CultureInfo.InvariantCulture)),
                ("restartInMs", ((long)delay.TotalMilliseconds).ToString(CultureInfo.InvariantCulture)));
            Thread.Sleep(delay);
        }
    }

    private int RunNodeOnce()
    {
        var start = new ProcessStartInfo(_locations.NodeExecutable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(_locations.NodeExecutable)!,
        };
        start.ArgumentList.Add("node");
        start.ArgumentList.Add("run");
        if (_locations.TestMode)
        {
            start.ArgumentList.Add(SupervisorLocations.TestModeOption);
        }

        try
        {
            using var node = Process.Start(start) ?? throw new InvalidOperationException("The node did not start.");
            _log.Write("node.started", ("pid", node.Id.ToString(CultureInfo.InvariantCulture)));
            node.WaitForExit();
            return node.ExitCode;
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            _log.Write("node.start_failed", ("errorType", exception.GetType().Name));
            return -1;
        }
    }
}

/// <summary>The supervisor's log: one line per event, <c>&lt;time&gt; &lt;event&gt; key=value ...</c>; rotated at 1 MB (two files).</summary>
internal sealed class SupervisorLog(string path, TimeProvider clock)
{
    private const long MaxBytes = 1_000_000;

    public void Write(string name, params (string Key, string Value)[] fields)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            if (File.Exists(path) && new FileInfo(path).Length > MaxBytes)
            {
                File.Move(path, path + ".1", overwrite: true);
            }

            var line = clock.GetUtcNow().UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture) + " " + name
                + string.Concat(fields.Select(field => " " + field.Key + "=" + field.Value)) + "\n";
            File.AppendAllText(path, line);
        }
        catch (IOException)
        {
            // The log never stops the supervisor.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
