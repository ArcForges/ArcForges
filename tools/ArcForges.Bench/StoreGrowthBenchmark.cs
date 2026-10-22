// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Bench;

/// <summary>
/// The store growth benchmark of 15-performance-targets section 2 and node-store.md section 4: generates synthetic attempts
/// through the store's real submit path and measures the database file. Each task is submitted from a session whose caller
/// environment comes from a captured shell (names kept, values synthetic), split into a content-addressed snapshot and sealed
/// secrets, recorded with <c>command_dedup</c> in a FULL commit, then run as one attempt (3 % of tasks retry once) whose
/// records (timeline, phases, processes, downsampled samples, cache usage, result-cache observations) are written as the
/// record builder and monitor would after it finishes. Housekeeping runs every 10 simulated minutes. The growth is the
/// database (and WAL) size after a final checkpoint minus the size of the new, empty store. Target: at most 50 MB per
/// 10,000 attempts, logs excluded (they are files, not store rows).
/// </summary>
/// <remarks>
/// The rows of later subsystems (task, attempt, records) are written with their node-store.sql columns; their exact content
/// is the workload profile stated in the result (<see cref="Profile"/>), not the output of those subsystems, which do not
/// exist yet. Time is simulated: 1,000 attempts per day. The node data key lives in the file-backed isolated secret store of the
/// benchmark's data root (as for a node started with <c>--test-mode</c>; 16-testing-strategy section 2), never in an OS-wide
/// secret store: the benchmark runs in the host verification and under the store tests (crash consistency), which must not
/// reach the user's Credential Manager or Secret Service. The key is outside the database, so the measured growth is unaffected.
/// </remarks>
internal static class StoreGrowthBenchmark
{
    public const long LimitBytesPer10000Attempts = 50_000_000;

    public const string Profile =
        "sessions of 100 tasks; per session 3 working directories; light 60 % (1-10 s, 1-3 processes, 2-4 segments), " +
        "build/test 32 % (20-180 s, 4-14 processes, 6-14 segments, 1-2 cache rows), heavy 8 % (180-900 s, 15-40 processes, " +
        "12-30 segments, 2-3 cache rows); samples every 10 s after downsampling; redacted arguments up to 160 characters; " +
        "result-cache observation on 20 % of build/test and heavy attempts; 3 % of tasks retried once; 1,000 attempts per simulated day";

    private const int TasksPerSession = 100;
    private const long MicrosPerSecond = 1_000_000;
    private static readonly DateTimeOffset Start = new(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly SecretNameMatcher Volatile = new(
        ["*SESSION*", "*PID*", "*PIPE*", "*SOCKET*", "*TOKEN*", "BAGGAGE", "SENTRY-TRACE", "WSL_INTEROP", "_", "OLDPWD", "PWD"]);

    private static readonly string[] LightCommands =
    [
        "git status --short", "git diff --stat", "git log --oneline -20", "ls -la src", "npm run lint", "dotnet --info",
        "python -m pyflakes src", "cargo fmt --check", "rg -n TODO src", "dotnet format --verify-no-changes",
    ];

    private static readonly string[] BuildCommands =
    [
        "dotnet test tests/ArcForges.Node.Store.Tests -c Release --no-build", "dotnet build ArcForges.slnx -c Release",
        "cargo test --workspace", "npm test", "pytest -q tests", "cmake --build build --parallel", "ctest --test-dir build",
    ];

    private static readonly string[] HeavyCommands =
    [
        "dotnet publish src/ArcForges.Host -c Release -r linux-x64", "cargo build --release --workspace",
        "cmake --build build --config Release --parallel 16", "npm run build", "./eng/test.ps1 -Suite ci",
    ];

    private static readonly string[] Executables =
    [
        "/usr/bin/dotnet", "/usr/lib/dotnet/dotnet", "C:/Program Files/dotnet/dotnet.exe", "/usr/bin/git", "/usr/bin/node",
        "/home/linuxbrew/.linuxbrew/bin/cargo", "/usr/bin/cc1plus", "/usr/bin/ld.lld", "C:/Windows/System32/conhost.exe",
        "/usr/bin/python3.14", "/usr/bin/bash", "C:/Program Files/Git/usr/bin/bash.exe",
    ];

    private static readonly string[] Categories = ["RESTORE", "BUILD", "TEST", "LINK_PACKAGE", "RUN", "NETWORK_WAIT", "DISK_WAIT", "FINALIZING"];

    private static readonly string[] Phases = ["restore", "build", "test", "pack", "publish", "link", "compile", "discover"];

    public static StoreGrowthResult Run(BenchOptions options, TextWriter acknowledgements)
    {
        var attempts = (int)(options.GetInt64("attempts", 1, 1_000_000) ?? 10_000);
        var seed = (ulong)(options.GetInt64("seed", 0, long.MaxValue) ?? 1);
        var printAcks = options.GetString("acks") switch
        {
            null or "false" => false,
            "true" => true,
            var other => throw new UsageException($"Option '--acks' is true or false, found '{other}'."),
        };
        var limitPer10000 = (long)((options.GetDouble("max-mb-per-10000", 0.001, 1_000_000) ?? 50) * 1_000_000);
        var name = options.GetString("name") ?? "node-store";
        var keep = options.GetString("data-root");
        var environmentFiles = options.GetAll("environment");
        if (environmentFiles.Count == 0)
        {
            throw new UsageException("At least one '--environment <captured environment JSON>' is required.");
        }

        options.GetString("output");
        options.EnsureAllUsed();
        var environments = environmentFiles.Select(LoadEnvironment).ToList();
        var dataRoot = keep is null
            ? Path.Combine(Path.GetTempPath(), "arcforges-store-growth-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8)))
            : Path.GetFullPath(keep);
        if (Directory.Exists(dataRoot) && Directory.EnumerateFileSystemEntries(dataRoot).Any())
        {
            throw new UsageException($"The data root {dataRoot} must be new or empty.");
        }

        var clock = new SimulatedClock(Start);
        var watch = Stopwatch.StartNew();
        try
        {
            var store = NodeStore.Open(new NodeStoreOptions { DataRoot = dataRoot, BootIdentity = "store-growth-benchmark", Clock = clock });
            store.Checkpoint();
            var baselineBytes = new FileInfo(StorePaths.Database(dataRoot)).Length;
            using var keys = new NodeDataKeyRing(store, NodeSecretStores.ForTestDataRoot(dataRoot));
            WorkloadCounts counts;
            try
            {
                counts = new Workload(store, keys, environments, seed, clock, printAcks ? acknowledgements : null).Run(attempts);
                store.Checkpoint();
            }
            finally
            {
                keys.DeleteKeys();
            }

            var tables = TableSizes(store);
            var distinct = store.Read(reader => Convert.ToInt64(reader.Scalar("SELECT count(*) FROM env_snapshot;"), CultureInfo.InvariantCulture));
            store.Dispose();
            var databaseBytes = new FileInfo(StorePaths.Database(dataRoot)).Length;
            var walPath = StorePaths.Database(dataRoot) + "-wal";
            var walBytes = File.Exists(walPath) ? new FileInfo(walPath).Length : 0;
            var limit = limitPer10000 * attempts / 10_000;
            return new StoreGrowthResult
            {
                Name = name,
                Attempts = attempts,
                Tasks = counts.Tasks,
                Sessions = counts.Sessions,
                SealedTasks = counts.SealedTasks,
                DistinctEnvironments = distinct,
                EnvironmentSources = [.. environments.Select(environment => $"{environment.Source} ({environment.Entries.Count} variables, {environment.Bytes} bytes)")],
                BaselineBytes = baselineBytes,
                DatabaseBytes = databaseBytes,
                WalBytes = walBytes,
                GrowthBytes = databaseBytes + walBytes - baselineBytes,
                BytesPerAttempt = Math.Round((double)(databaseBytes + walBytes - baselineBytes) / attempts, 1),
                LimitBytes = limit,
                LimitBytesPer10000Attempts = limitPer10000,
                Pass = databaseBytes + walBytes - baselineBytes <= limit,
                DurationMs = watch.ElapsedMilliseconds,
                Profile = Profile,
                Tables = tables,
                Environment = BenchEnvironment.Current(),
            };
        }
        finally
        {
            if (keep is null && Directory.Exists(dataRoot))
            {
                Directory.Delete(dataRoot, recursive: true);
            }
        }
    }

    private static List<TableSize> TableSizes(NodeStore store) => store.Read(reader =>
    {
        var rows = new Dictionary<string, long>(StringComparer.Ordinal);
        var bytes = new Dictionary<string, long>(StringComparer.Ordinal);
        var owners = new Dictionary<string, string>(StringComparer.Ordinal);
        using (var command = reader.CreateCommand("SELECT name, tbl_name, type FROM sqlite_schema WHERE type IN ('table', 'index');"))
        using (var row = command.ExecuteReader())
        {
            while (row.Read())
            {
                owners[row.GetString(0)] = row.GetString(1);
            }
        }

        try
        {
            using var command = reader.CreateCommand("SELECT name, sum(pgsize) FROM dbstat GROUP BY name;");
            using var row = command.ExecuteReader();
            while (row.Read())
            {
                var owner = owners.GetValueOrDefault(row.GetString(0), row.GetString(0));
                bytes[owner] = bytes.GetValueOrDefault(owner) + row.GetInt64(1);
            }
        }
        catch (Microsoft.Data.Sqlite.SqliteException)
        {
            // dbstat is optional in SQLite builds; the file size is the measurement either way.
        }

        foreach (var table in owners.Values.Distinct(StringComparer.Ordinal))
        {
            // Table names come from sqlite_schema of this store, never from input.
            rows[table] = Convert.ToInt64(reader.Scalar($"SELECT count(*) FROM \"{table.Replace("\"", "\"\"", StringComparison.Ordinal)}\";"), CultureInfo.InvariantCulture);
        }

        return rows.Where(pair => pair.Value > 0)
            .Select(pair => new TableSize { Table = pair.Key, Rows = pair.Value, Bytes = bytes.TryGetValue(pair.Key, out var size) ? size : null })
            .OrderByDescending(size => size.Bytes)
            .ThenBy(size => size.Table, StringComparer.Ordinal)
            .ToList();
    });

    private static CapturedEnvironment LoadEnvironment(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        var root = document.RootElement;
        var entries = root.GetProperty("entries").EnumerateArray()
            .Select(entry => new KeyValuePair<string, string>(entry.GetProperty("name").GetString()!, entry.GetProperty("value").GetString()!))
            .ToList();
        var source = root.TryGetProperty("source", out var label) ? label.GetString() ?? Path.GetFileName(path) : Path.GetFileName(path);
        return new CapturedEnvironment(source, entries, entries.Sum(entry => Encoding.UTF8.GetByteCount(entry.Key) + Encoding.UTF8.GetByteCount(entry.Value) + 2));
    }

    private sealed record CapturedEnvironment(string Source, IReadOnlyList<KeyValuePair<string, string>> Entries, int Bytes);

    private sealed record WorkloadCounts(int Tasks, int Sessions, int SealedTasks);

    /// <summary>A clock the workload advances: the benchmark's simulated time (workload input, not a substitute for a system).</summary>
    private sealed class SimulatedClock(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    /// <summary>SplitMix64: deterministic workload choices for a seed.</summary>
    private sealed class Choices(ulong seed)
    {
        private ulong _state = seed;

        public ulong Next()
        {
            var z = _state += 0x9E3779B97F4A7C15UL;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
            return z ^ (z >> 31);
        }

        public int Between(int low, int high) => low + (int)(Next() % (ulong)(high - low + 1));

        public bool Chance(int percent) => Next() % 100 < (ulong)percent;

        public T Pick<T>(T[] items) => items[(int)(Next() % (ulong)items.Length)];

        public string Text(int length)
        {
            const string alphabet = "abcdefghijklmnopqrstuvwxyz0123456789/._-";
            var buffer = new char[length];
            for (var index = 0; index < length; index++)
            {
                buffer[index] = alphabet[(int)(Next() % (ulong)alphabet.Length)];
            }

            return new string(buffer);
        }
    }

    private sealed class Workload(NodeStore store, NodeDataKeyRing keys, IReadOnlyList<CapturedEnvironment> environments, ulong seed,
        SimulatedClock clock, TextWriter? acknowledgements)
    {
        private readonly TaskSecrets _secrets = new(store, keys);
        private readonly Choices _choices = new(seed);
        private readonly byte[] _nodeId = store.Metadata.NodeId.ToArray();
        private long _nextHousekeeping;

        public WorkloadCounts Run(int attempts)
        {
            var tasks = 0;
            var sessions = 0;
            var sealedTasks = 0;
            var written = 0;
            var stepMicros = 86_400L * MicrosPerSecond / 1_000;
            _nextHousekeeping = StoreTime.ToMicroseconds(clock.Now) + (600 * MicrosPerSecond);
            while (written < attempts)
            {
                var session = NewSession(sessions++);
                for (var index = 0; index < TasksPerSession && written < attempts; index++)
                {
                    var submittedAt = StoreTime.ToMicroseconds(Start) + ((long)written * stepMicros);
                    clock.Now = StoreTime.FromMicroseconds(submittedAt);
                    Housekeeping(submittedAt);
                    var cwd = _choices.Pick(session.WorkingDirectories);
                    var (taskId, sealedValues, kind) = Submit(session, cwd, index);
                    tasks++;
                    sealedTasks += sealedValues ? 1 : 0;
                    var retried = _choices.Chance(3) && written + 1 < attempts;
                    var attemptCount = retried ? 2 : 1;
                    var finishedAt = submittedAt;
                    for (var number = 1; number <= attemptCount; number++)
                    {
                        finishedAt = RunAttempt(taskId, kind, number, finishedAt + (_choices.Between(0, 5) * MicrosPerSecond), number == attemptCount);
                        written++;
                    }

                    store.Write(transaction => TaskSecrets.SchedulePurge(transaction, taskId, finishedAt, TimeSpan.FromHours(24)));
                }
            }

            return new WorkloadCounts(tasks, sessions, sealedTasks);
        }

        private void Housekeeping(long now)
        {
            while (now >= _nextHousekeeping)
            {
                store.Commands.PurgeExpired();
                _secrets.PurgeDue();
                store.Environments.DeleteUnreferenced();
                _nextHousekeeping += 600 * MicrosPerSecond;
            }
        }

        private Session NewSession(int number)
        {
            var captured = environments[number % environments.Count];
            var windows = captured.Source.StartsWith("windows", StringComparison.Ordinal);
            var sessionId = StoreIds.NewUuid7(clock);
            var workspace = _choices.Between(0, 2);
            var root = windows ? $"C:/work/project-{workspace}" : $"/home/user/work/project-{workspace}";
            string[] directories = [root, root + "/src", root + "/tests/" + _choices.Text(12)];
            var variables = new List<KeyValuePair<string, string>>(captured.Entries.Count);
            foreach (var (key, value) in captured.Entries)
            {
                // Per-session values (session IDs, PIDs, pipes, tokens, tracing headers) differ between sessions.
                variables.Add(new(key, Volatile.IsSecret(key) && value.Length > 0 ? _choices.Text(value.Length) : value));
            }

            store.Write(transaction => transaction.Execute(
                """
                INSERT INTO session (session_id, client, client_name, client_version, client_session_id, source, state, cwd, workspace_id,
                                     agent_root_pid, agent_root_start, transcript_path, model, routing_mode, started_at, last_activity_at, rev)
                VALUES ($id, 1, 'claude-code', '2.4.1', $clientSession, 1, 1, $cwd, NULL, $pid, $now, NULL, NULL, 0, $now, $now, 0);
                """,
                ("$id", sessionId),
                ("$clientSession", Convert.ToHexStringLower(sessionId)),
                ("$cwd", root),
                ("$pid", _choices.Between(1_000, 60_000)),
                ("$now", transaction.NowMicroseconds)));
            return new Session(sessionId, windows, variables, directories);
        }

        private (byte[] TaskId, bool Sealed, CommandClass Kind) Submit(Session session, string cwd, int index)
        {
            var kind = _choices.Between(0, 99) switch
            {
                < 60 => CommandClass.Light,
                < 92 => CommandClass.Build,
                _ => CommandClass.Heavy,
            };
            var command = _choices.Pick(kind switch
            {
                CommandClass.Light => LightCommands,
                CommandClass.Build => BuildCommands,
                _ => HeavyCommands,
            });
            var spec = new TaskSpec
            {
                Command = new CommandSpec { Shell = new ShellCommand { Kind = session.Windows ? ShellKind.Pwsh : ShellKind.Bash, Script = command } },
                WorkingDirectory = cwd,
                Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Caller },
                Pool = "agents",
                Priority = Priority.Normal,
                Kind = TaskKind.Command,
                SideEffect = SideEffectClass.Unknown,
                Title = command.Length <= 60 ? command : command[..60],
            };
            foreach (var (key, value) in session.Variables)
            {
                spec.Environment.CallerEnvironment[key] = key switch
                {
                    "PWD" => cwd,
                    "OLDPWD" => session.WorkingDirectories[0],
                    _ => value,
                };
            }

            var request = new TaskServiceSubmitTaskRequest
            {
                Meta = new RequestMeta { CommandId = new Id { Value = ByteString.CopyFrom(StoreIds.NewUuid7(clock)) } },
                Spec = spec,
                SessionId = new Id { Value = ByteString.CopyFrom(session.Id) },
                CancelWhenCallerGone = true,
                JoinExisting = true,
            };
            var commandId = request.Meta.CommandId.Value.ToByteArray();
            var taskId = StoreIds.NewUuid7(clock);
            var sealedValues = false;
            var result = store.Commands.Execute(commandId, "arcforges.node.v1.TaskService/SubmitTask", PayloadDigest.Compute(request),
                Origin.Agent, transaction =>
                {
                    var split = SubmittedEnvironment.Split(spec, SecretNameMatcher.Default);
                    var envDigest = split.Snapshot is null ? null : EnvSnapshots.Reference(transaction, split.Snapshot);
                    var redacted = split.RedactedSpec.ToByteArray();
                    var actor = new ActorRef
                    {
                        Origin = Origin.Agent,
                        ClientKind = ClientKind.Hook,
                        SessionId = new Id { Value = ByteString.CopyFrom(session.Id) },
                        OsUser = "user",
                        ClientName = "claude-code",
                    };
                    var now = transaction.NowMicroseconds;
                    transaction.Execute(
                        """
                        INSERT INTO task (task_id, state, kind, title, command_summary, spec, env_digest, spec_digest, owner, owner_origin,
                                          owner_session_id, workspace_id, pool, priority, effective_priority, side_effect, side_effect_source,
                                          command_fingerprint, command_digest, created_at, queued_at, rev)
                        VALUES ($id, 1, 1, $title, $summary, $spec, $env, $specDigest, $owner, 3, $session, NULL, 'agents', 3, 3, 4, 1,
                                $fingerprint, $commandDigest, $now, $now, 0);
                        """,
                        ("$id", taskId),
                        ("$title", spec.Title),
                        ("$summary", command),
                        ("$spec", redacted),
                        ("$env", envDigest),
                        ("$specDigest", SHA256.HashData(redacted)),
                        ("$owner", actor.ToByteArray()),
                        ("$session", session.Id),
                        ("$fingerprint", command.Split(' ')[0] + ":" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(command)))[..16]),
                        ("$commandDigest", SHA256.HashData(Encoding.UTF8.GetBytes(command + "\n" + cwd + "\n" + Convert.ToHexStringLower(envDigest ?? [])))),
                        ("$now", now));
                    if (kind != CommandClass.Light)
                    {
                        transaction.Execute(
                            "INSERT INTO task_concurrency_key (task_id, concurrency_key, mode, source, released_at) VALUES ($id, $key, 1, 2, NULL);",
                            ("$id", taskId),
                            ("$key", "tool:" + command.Split(' ')[0] + ":" + session.WorkingDirectories[0]));
                    }

                    if (split.Secrets is not null)
                    {
                        _secrets.Seal(transaction, taskId, split.Secrets);
                        sealedValues = true;
                    }

                    return new TaskServiceSubmitTaskResponse
                    {
                        Value = new TaskServiceSubmitTaskValue
                        {
                            Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened },
                            TaskId = new Id { Value = ByteString.CopyFrom(taskId) },
                            State = TaskState.Queued,
                            Queue = new QueueInfo { Position = (uint)((index % 4) + 1) },
                        },
                    }.ToByteArray();
                });
            if (result.Error is not null || result.Replayed)
            {
                throw new InvalidOperationException("A fresh command ID was not executed exactly once.");
            }

            acknowledgements?.WriteLine("ack " + Convert.ToHexStringLower(commandId));
            acknowledgements?.Flush();
            return (taskId, sealedValues, kind);
        }

        private long RunAttempt(byte[] taskId, CommandClass kind, int number, long startedAt, bool last)
        {
            var seconds = kind switch
            {
                CommandClass.Light => _choices.Between(1, 10),
                CommandClass.Build => _choices.Between(20, 180),
                _ => _choices.Between(180, 900),
            };
            var finishedAt = startedAt + (seconds * MicrosPerSecond);
            var attemptId = StoreIds.NewUuid7(clock);
            var memory = kind switch
            {
                CommandClass.Light => 128L << 20,
                CommandClass.Build => 2L << 30,
                _ => 6L << 30,
            };
            clock.Now = StoreTime.FromMicroseconds(startedAt);
            store.Write(transaction =>
            {
                transaction.Execute(
                    """
                    INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, container_name, root_pid, root_start,
                                         boot_identity, request_cpu_millicores, request_mem_expected_bytes, request_mem_ceiling_bytes,
                                         request_source, accounted_mem_bytes, tool, operation, tool_parallelism, created_at, started_at, rev)
                    VALUES ($id, $task, $number, 1, 4, $node, $container, $pid, $start, 'store-growth-benchmark', $cpu, $memory, $ceiling,
                            $source, $memory, $tool, $operation, $parallelism, $start, $start, 0);
                    """,
                    ("$id", attemptId),
                    ("$task", taskId),
                    ("$number", number),
                    ("$node", _nodeId),
                    ("$container", "arcforges-a-" + Convert.ToHexStringLower(attemptId) + ".service"),
                    ("$pid", _choices.Between(1_000, 4_000_000)),
                    ("$start", startedAt),
                    ("$cpu", kind == CommandClass.Light ? 250 : 4_000),
                    ("$memory", memory),
                    ("$ceiling", memory * 2),
                    ("$source", kind == CommandClass.Light ? 5 : 3),
                    ("$tool", kind == CommandClass.Light ? null : "dotnet"),
                    ("$operation", kind == CommandClass.Light ? null : "test"),
                    ("$parallelism", kind == CommandClass.Light ? null : 8));
                transaction.Execute(
                    "UPDATE task SET state = 4, started_at = $start, current_attempt_id = $attempt, attempt_count = $number, rev = rev + 1 WHERE task_id = $task;",
                    ("$start", startedAt),
                    ("$attempt", attemptId),
                    ("$number", number),
                    ("$task", taskId));
            });

            clock.Now = StoreTime.FromMicroseconds(finishedAt);
            var failed = !last || _choices.Chance(8);
            store.Write(transaction => Finish(transaction, taskId, attemptId, kind, startedAt, finishedAt, seconds, memory, failed, last));
            return finishedAt;
        }

        private void Finish(StoreTransaction transaction, byte[] taskId, byte[] attemptId, CommandClass kind, long startedAt, long finishedAt,
            int seconds, long memory, bool failed, bool last)
        {
            var (processes, segments, phases, caches) = kind switch
            {
                CommandClass.Light => (_choices.Between(1, 3), _choices.Between(2, 4), _choices.Between(0, 2), 0),
                CommandClass.Build => (_choices.Between(4, 14), _choices.Between(6, 14), _choices.Between(3, 8), _choices.Between(1, 2)),
                _ => (_choices.Between(15, 40), _choices.Between(12, 30), _choices.Between(6, 12), _choices.Between(2, 3)),
            };
            var output = kind == CommandClass.Light ? _choices.Between(100, 20_000) : _choices.Between(20_000, 4_000_000);
            transaction.Execute(
                """
                UPDATE attempt SET state = 9, finished_at = $end, exit_code = $exit, termination_reason = 1, effect = 2,
                       cpu_time_ms = $cpuTime, mem_peak_bytes = $peak, io_read_bytes = $read, io_write_bytes = $write,
                       stdout_bytes = $output, stderr_bytes = $error, stdout_offset = $output, stderr_offset = $error, index_offset = $index,
                       output_retained_until = $retained, rev = rev + 1
                WHERE attempt_id = $id;
                """,
                ("$end", finishedAt),
                ("$exit", failed ? 1 : 0),
                ("$cpuTime", seconds * _choices.Between(200, 6_000)),
                ("$peak", memory / 2 + _choices.Between(0, 1 << 20)),
                ("$read", _choices.Between(1 << 16, 1 << 30)),
                ("$write", _choices.Between(1 << 12, 1 << 28)),
                ("$output", output),
                ("$error", output / 20),
                ("$index", output / 120 * 22),
                ("$retained", finishedAt + (14L * 86_400 * MicrosPerSecond)),
                ("$id", attemptId));

            var span = finishedAt - startedAt;
            for (var segment = 0; segment < segments; segment++)
            {
                var from = startedAt + (span * segment / segments);
                var to = startedAt + (span * (segment + 1) / segments);
                transaction.Execute(
                    "INSERT INTO timeline_segment (attempt_id, start_at, end_at, category, confidence, evidence) VALUES ($id, $from, $to, $category, $confidence, $evidence);",
                    ("$id", attemptId),
                    ("$from", from),
                    ("$to", to),
                    ("$category", _choices.Pick(Categories)),
                    ("$confidence", _choices.Between(1, 3)),
                    ("$evidence", "adapter marker " + _choices.Pick(Phases) + "; cpu " + _choices.Between(1, 1_600) + "%; " + _choices.Text(_choices.Between(10, 50))));
            }

            for (var phase = 0; phase < phases; phase++)
            {
                transaction.Execute(
                    "INSERT INTO phase_event (attempt_id, at, phase, source) VALUES ($id, $at, $phase, $source);",
                    ("$id", attemptId),
                    ("$at", startedAt + (span * phase / Math.Max(1, phases)) + phase),
                    ("$phase", Phases[phase % Phases.Length]),
                    ("$source", "adapter:dotnet"));
            }

            var parent = _choices.Between(1_000, 4_000_000);
            for (var process = 0; process < processes; process++)
            {
                var arguments = _choices.Between(0, 160);
                transaction.Execute(
                    """
                    INSERT INTO process_record (attempt_id, pid, start_at, parent_pid, executable, arguments_redacted, first_seen, last_seen, mem_peak_bytes, label)
                    VALUES ($id, $pid, $start, $parent, $exe, $arguments, $first, $last, $peak, 1);
                    """,
                    ("$id", attemptId),
                    ("$pid", parent + process + 1),
                    ("$start", startedAt + process),
                    ("$parent", process == 0 ? parent : parent + _choices.Between(1, process)),
                    ("$exe", _choices.Pick(Executables)),
                    ("$arguments", arguments == 0 ? null : _choices.Text(arguments)),
                    ("$first", startedAt + process),
                    ("$last", finishedAt),
                    ("$peak", _choices.Between(1 << 20, 1 << 30)));
            }

            // Attempt samples are kept every 10 s once the attempt finished (node-store.md resource_sample retention).
            for (var at = startedAt; at < finishedAt || at == startedAt; at += 10 * MicrosPerSecond)
            {
                transaction.Execute(
                    """
                    INSERT INTO resource_sample (scope, subject_id, at, resolution_ms, cpu_millicores, cpu_time_ms, mem_bytes, mem_peak_bytes,
                                                 process_count, io_read_bytes, io_write_bytes)
                    VALUES (3, $id, $at, 10000, $cpu, $cpuTime, $mem, $peak, $count, $read, $write);
                    """,
                    ("$id", attemptId),
                    ("$at", at),
                    ("$cpu", _choices.Between(0, 16_000)),
                    ("$cpuTime", _choices.Between(0, 1_000_000)),
                    ("$mem", _choices.Between(1 << 20, int.MaxValue)),
                    ("$peak", _choices.Between(1 << 20, int.MaxValue)),
                    ("$count", processes),
                    ("$read", _choices.Between(0, 1 << 30)),
                    ("$write", _choices.Between(0, 1 << 28)));
            }

            for (var cache = 0; cache < caches; cache++)
            {
                transaction.Execute(
                    """
                    INSERT INTO attempt_cache_usage (attempt_id, cache_id, kind, bytes_added, hits, misses, cache_writes, packages_installed,
                                                     packages_reused, downloaded_bytes, peer_filled_bytes, counters_source, attribution, window_id, measured_at)
                    VALUES ($id, $cache, $kind, $added, $hits, $misses, $writes, NULL, $reused, NULL, NULL, $source, 1, NULL, $at);
                    """,
                    ("$id", attemptId),
                    ("$cache", SHA256.HashData(Encoding.UTF8.GetBytes("cache" + cache))[..16]),
                    ("$kind", cache == 0 ? "nuget" : "sccache"),
                    ("$added", _choices.Between(0, 50_000_000)),
                    ("$hits", _choices.Between(0, 2_000)),
                    ("$misses", _choices.Between(0, 200)),
                    ("$writes", _choices.Between(0, 200)),
                    ("$reused", _choices.Between(0, 300)),
                    ("$source", cache == 0 ? "adapter-output" : "sccache-server"),
                    ("$at", finishedAt));
            }

            if (kind != CommandClass.Light && _choices.Chance(20))
            {
                transaction.Execute(
                    """
                    INSERT INTO result_cache_observation (attempt_id, workspace_id, action_key, output_manifest_digest, succeeded, would_hit, observed_at)
                    VALUES ($id, NULL, $key, $digest, $succeeded, $hit, $at);
                    """,
                    ("$id", attemptId),
                    ("$key", RandomNumberGenerator.GetBytes(32)),
                    ("$digest", RandomNumberGenerator.GetBytes(32)),
                    ("$succeeded", failed ? 0 : 1),
                    ("$hit", _choices.Chance(30) ? 1 : 0),
                    ("$at", finishedAt));
            }

            transaction.Execute(
                "UPDATE task SET state = $state, finished_at = $end, retry_at = $retry, rev = rev + 1 WHERE task_id = $task;",
                ("$state", last ? (failed ? 8 : 7) : 6),
                ("$end", last ? finishedAt : null),
                ("$retry", last ? null : finishedAt + (5 * MicrosPerSecond)),
                ("$task", taskId));
        }

        private enum CommandClass
        {
            Light,
            Build,
            Heavy,
        }

        private sealed record Session(byte[] Id, bool Windows, IReadOnlyList<KeyValuePair<string, string>> Variables, string[] WorkingDirectories);
    }
}
