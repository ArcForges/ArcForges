// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// TaskService against a real node in the test process with the real Windows execution platform (node-component layer; env=windows-real):
/// submission persisted before the receipt, the exact argument vector, working directory and environment, captured streams byte-identical
/// to a direct run, stdin modes, sealed secrets, the batch refusal through the API (T-03), validation, waits, attach, output reads, manual
/// retry, pin and purge.
/// </summary>
[Trait("env", "windows-real")]
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class TaskServiceTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 120_000)]
    public async Task ACommandReceivesTheExactArgumentsLikeADirectRunAndItsExitCodeIsRecorded()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var work = Directory.CreateDirectory(Path.Combine(node.Root, "work dir ä")).FullName;
        string[] argv = [Tasks.TestLoad, "args", "plain", "", "two words", "quote\"inside", "trailing\\", "back\\\\\"slash", "unicode äöü 中文 🚀", "%PATH%", "!x!", "a&b|c<d>e^"];

        var taskId = await Tasks.SubmitAsync(channel, Tasks.Argv(work, argv));
        var task = await Tasks.WaitAsync(channel, taskId);
        Assert.Equal(TaskState.Succeeded, task.State);
        Assert.Equal(TerminationReason.Exited, task.CurrentAttempt.Result.TerminationReason);
        Assert.Equal(0, task.CurrentAttempt.Result.ExitCode);
        var managed = await Tasks.ReadAllAsync(channel, task.CurrentAttempt.AttemptId, OutputStream.Stdout);
        var direct = Tasks.Direct(work, argv);
        Assert.Equal(Encoding.UTF8.GetString(direct.Stdout), Encoding.UTF8.GetString(managed));
        using var document = JsonDocument.Parse(managed);
        Assert.Equal(argv[2..], document.RootElement.GetProperty("argv").EnumerateArray().Select(item => item.GetString()));
        Assert.Equal(work, document.RootElement.GetProperty("cwd").GetString());

        var failing = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, Tasks.Argv(work, Tasks.Cmd, "/d", "/c", "exit 7")));
        Assert.Equal(TaskState.Failed, failing.State);
        Assert.Equal(7, failing.CurrentAttempt.Result.ExitCode);
        Assert.Equal(EffectCertainty.Happened, failing.CurrentAttempt.Result.Effect);
        var exception = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, Tasks.Argv(work, Tasks.Cmd, "/d", "/c", "exit -1073741819")));
        Assert.Equal(0xC0000005u, exception.CurrentAttempt.Result.WindowsStatus);
    }

    [Fact(Timeout = 180_000)]
    public async Task CapturedStreamsAreByteIdenticalToADirectRun()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        string[] argv = [Tasks.TestLoad, "output", "--bytes", "16777216", "--line-bytes", "137", "--stream", "both", "--seed", "7"];
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, argv)));
        Assert.Equal(TaskState.Succeeded, task.State);
        var attempt = task.CurrentAttempt.AttemptId;
        var stdout = await Tasks.ReadAllAsync(channel, attempt, OutputStream.Stdout);
        var stderr = await Tasks.ReadAllAsync(channel, attempt, OutputStream.Stderr);
        var merged = await Tasks.ReadAllAsync(channel, attempt, OutputStream.Merged);
        var direct = Tasks.Direct(node.Root, argv);
        Assert.Equal(direct.ExitCode, task.CurrentAttempt.Result.ExitCode);
        Assert.Equal(SHA256.HashData(direct.Stdout), SHA256.HashData(stdout));
        Assert.Equal(SHA256.HashData(direct.Stderr), SHA256.HashData(stderr));
        Assert.Equal(stdout.Length + stderr.Length, merged.Length);
    }

    [Fact(Timeout = 120_000)]
    public async Task StdinIsNoneBytesAFileOrAStreamFromTheAttachedCaller()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var payload = Encoding.UTF8.GetBytes("line one\r\nzwei ä\n\0binary\xff end");

        var none = Tasks.Argv(node.Root, Tasks.TestLoad, "echo");
        none.Stdin = new StdinSpec { Mode = StdinMode.None };
        var noneTask = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, none));
        Assert.Empty(await Tasks.ReadAllAsync(channel, noneTask.CurrentAttempt.AttemptId, OutputStream.Stdout));

        var bytes = Tasks.Argv(node.Root, Tasks.TestLoad, "echo");
        bytes.Stdin = new StdinSpec { Mode = StdinMode.Bytes, Data = ByteString.CopyFrom(payload) };
        var bytesTask = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, bytes));
        Assert.Equal(payload, await Tasks.ReadAllAsync(channel, bytesTask.CurrentAttempt.AttemptId, OutputStream.Stdout));

        var input = Path.Combine(node.Root, "input.bin");
        File.WriteAllBytes(input, payload);
        var file = Tasks.Argv(node.Root, Tasks.TestLoad, "echo");
        file.Stdin = new StdinSpec { Mode = StdinMode.File, FilePath = input };
        var fileTask = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, file));
        Assert.Equal(payload, await Tasks.ReadAllAsync(channel, fileTask.CurrentAttempt.AttemptId, OutputStream.Stdout));

        var stream = Tasks.Argv(node.Root, Tasks.TestLoad, "echo");
        stream.Stdin = new StdinSpec { Mode = StdinMode.Stream };
        var streamId = await Tasks.SubmitAsync(channel, stream);
        using var call = channel.Tasks.AttachTask(new TaskServiceAttachTaskRequest { Meta = Tasks.Meta(), TaskId = streamId, WantStdin = true }, cancellationToken: Ct);
        Id? attach = null;
        var output = new MemoryStream();
        AttemptResult? result = null;
        while (await call.ResponseStream.MoveNext(Ct))
        {
            var frame = call.ResponseStream.Current;
            if (frame.FrameCase == TaskServiceAttachTaskFrame.FrameOneofCase.Started && frame.Started.StdinGranted && attach is null)
            {
                attach = frame.Started.AttachId;
                ulong offset = 0;
                foreach (var chunk in payload.Chunk(7))
                {
                    var written = await channel.Tasks.WriteTaskInputAsync(new TaskServiceWriteTaskInputRequest
                    {
                        Meta = Tasks.Meta(),
                        TaskId = streamId,
                        AttachId = attach,
                        Offset = offset,
                        Data = ByteString.CopyFrom(chunk),
                    }, cancellationToken: Ct);
                    Assert.Null(written.Error);
                    offset = written.Value.AcceptedThrough;

                    // A repeated write (a retry) is deduplicated by its offset.
                    var again = await channel.Tasks.WriteTaskInputAsync(new TaskServiceWriteTaskInputRequest
                    {
                        Meta = Tasks.Meta(),
                        TaskId = streamId,
                        AttachId = attach,
                        Offset = offset - (ulong)chunk.Length,
                        Data = ByteString.CopyFrom(chunk),
                    }, cancellationToken: Ct);
                    Assert.Equal(offset, again.Value.AcceptedThrough);
                }

                var closed = await channel.Tasks.CloseTaskInputAsync(new TaskServiceCloseTaskInputRequest { Meta = Tasks.Meta(), TaskId = streamId, AttachId = attach }, cancellationToken: Ct);
                Assert.Null(closed.Error);
            }
            else if (frame.FrameCase == TaskServiceAttachTaskFrame.FrameOneofCase.Output)
            {
                output.Write(frame.Output.Data.Span);
            }
            else if (frame.FrameCase == TaskServiceAttachTaskFrame.FrameOneofCase.Result)
            {
                result = frame.Result;
            }
        }

        Assert.NotNull(attach);
        Assert.Equal(0, result!.ExitCode);
        Assert.Equal(payload, output.ToArray());

        // Writes without the current attach are refused.
        var stale = await channel.Tasks.WriteTaskInputAsync(new TaskServiceWriteTaskInputRequest
        {
            Meta = Tasks.Meta(),
            TaskId = streamId,
            AttachId = CommandIds.New(),
            Offset = 0,
            Data = Tasks.Bytes("x"),
        }, cancellationToken: Ct);
        Assert.NotNull(stale.Error);
    }

    [Fact(Timeout = 120_000)]
    public async Task SecretShapedValuesAreSealedAndOnlyThePresenceIsRecorded()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var spec = Tasks.Argv(node.Root, Tasks.Cmd, "/d", "/c", "echo [%API_TOKEN%] [%PLAIN_VALUE%] [%ARCFORGES_TASK_ID%] [%TMP%]");
        spec.Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Caller };
        spec.Environment.CallerEnvironment["SystemRoot"] = Environment.GetEnvironmentVariable("SystemRoot")!;
        spec.Environment.CallerEnvironment["GITHUB_TOKEN"] = "caller-secret-value";
        spec.Environment.Set["API_TOKEN"] = "s3cret-value";
        spec.Environment.Set["PLAIN_VALUE"] = "visible";
        var taskId = await Tasks.SubmitAsync(channel, spec);
        var task = await Tasks.WaitAsync(channel, taskId);
        var output = Encoding.UTF8.GetString(await Tasks.ReadAllAsync(channel, task.CurrentAttempt.AttemptId, OutputStream.Stdout));
        Assert.Contains("[s3cret-value] [visible]", output, StringComparison.Ordinal);
        Assert.Contains($"[{IdText.Format(taskId)}]", output, StringComparison.Ordinal);
        Assert.Contains(Path.Combine(node.DataRoot, "tmp", IdText.Format(task.CurrentAttempt.AttemptId)), output, StringComparison.OrdinalIgnoreCase);

        // R-EXE-017: records show secret-shaped names as presence only; the values live sealed in task_secret.
        var full = await Tasks.GetAsync(channel, taskId, full: true);
        Assert.Equal("visible", full.Spec.Environment.Set["PLAIN_VALUE"]);
        Assert.False(full.Spec.Environment.Set.ContainsKey("API_TOKEN"));
        Assert.Empty(full.Spec.Environment.CallerEnvironment);
        var stored = node.Runtime.Store.Read(reader => (reader.Scalar("SELECT names_json FROM task_secret WHERE task_id = $id;", ("$id", taskId.Value.ToByteArray())) as string,
            reader.Scalar("SELECT count(*) FROM task WHERE instr(spec, $value) > 0;", ("$value", Encoding.UTF8.GetBytes("s3cret-value")))));
        Assert.Equal("[\"API_TOKEN\",\"GITHUB_TOKEN\"]", stored.Item1);
        Assert.Equal(0L, stored.Item2);
    }

    [Fact(Timeout = 120_000)]
    public async Task UnsafeBatchArgumentsAreRefusedAndSafeOnesReachTheBatchFileUnchanged()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows batch files.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var script = Path.Combine(node.Root, "probe.cmd");
        File.WriteAllText(script, $"@\"{Tasks.TestLoad}\" args %*\r\n");

        foreach (var unsafeArgument in (string[])["\"&calc.exe", "x\" | whoami", "!PATH!", "line\nbreak", "\"%PATH%\"", "quote\"only", "\"", "\"two words\"", "a\\\"b"])
        {
            var refused = await Tasks.SubmitRawAsync(channel, Tasks.Argv(node.Root, script, "ok", unsafeArgument));
            Assert.Equal(("unsafe_batch_argument", ErrorCategory.Validation), (refused.Error.Code, refused.Error.Category));
            Assert.Equal("2", refused.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, refused.Error.Effect);
        }

        string[] safe = ["two words", "a&b", "x|y", "<in>", "caret^", "50%", "%PATH%", "(paren)", "comma,semi;eq=", "C:\\dir with space\\", "next",
            "trailing\\\\ two", "\\\\server\\share x\\", "a\\b c", "C:\\nospace\\"];
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, [script, .. safe])));
        Assert.Equal(TaskState.Succeeded, task.State);
        using var document = JsonDocument.Parse(await Tasks.ReadAllAsync(channel, task.CurrentAttempt.AttemptId, OutputStream.Stdout));
        Assert.Equal(safe, document.RootElement.GetProperty("argv").EnumerateArray().Select(item => item.GetString()));
    }

    [Fact(Timeout = 60_000)]
    public async Task InvalidSubmissionsAreRefusedBeforeAnythingIsStored()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var notFound = await Tasks.SubmitRawAsync(channel, Tasks.Argv(node.Root, "arcforges-no-such-program-xyz"));
        Assert.Equal(("program_not_found", "arcforges-no-such-program-xyz"), (notFound.Error.Code, notFound.Error.Details.State.Reason));
        var missingDirectory = await Tasks.SubmitRawAsync(channel, Tasks.Argv(Path.Combine(node.Root, "missing"), Tasks.Cmd));
        Assert.Equal(("path_not_found", "working_directory"), (missingDirectory.Error.Code, missingDirectory.Error.Details.State.Reason));
        var relative = await Tasks.SubmitRawAsync(channel, Tasks.Argv("relative", Tasks.Cmd));
        Assert.Equal("invalid_argument", relative.Error.Code);
        var shell = Tasks.Argv(node.Root);
        shell.Command = new CommandSpec { Shell = new ShellCommand { Kind = ShellKind.Bash, Script = "echo", ShellPath = Path.Combine(node.Root, "no-bash.exe") } };
        Assert.Equal("unsupported_shell", (await Tasks.SubmitRawAsync(channel, shell)).Error.Code);
        var dependency = Tasks.Argv(node.Root, Tasks.Cmd);
        dependency.DependsOn.Add(new Dependency { TaskId = CommandIds.New() });
        Assert.Equal("invalid_argument", (await Tasks.SubmitRawAsync(channel, dependency)).Error.Code);
        var tooLong = Tasks.Argv(node.Root, Tasks.Cmd, "/c", new string('x', 40_000));
        Assert.Equal("invalid_argument", (await Tasks.SubmitRawAsync(channel, tooLong)).Error.Code);
        var interactive = Tasks.Argv(node.Root, Tasks.Cmd);
        interactive.Priority = Priority.Interactive;
        Assert.Equal("permission_denied", (await Tasks.SubmitRawAsync(channel, interactive)).Error.Code);

        var list = await channel.Tasks.ListTasksAsync(new TaskServiceListTasksRequest { Meta = Tasks.Meta() }, cancellationToken: Ct);
        Assert.Empty(list.Value.Tasks);
    }

    [Fact(Timeout = 120_000)]
    public async Task ASubmissionIsIdempotentByCommandIdAndListedNewestFirst()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.Cmd, "/d", "/c", "exit 0") };
        var first = await channel.Tasks.SubmitTaskAsync(request, cancellationToken: Ct);
        var replay = await channel.Tasks.SubmitTaskAsync(request, cancellationToken: Ct);
        Assert.Equal(first.Value.TaskId, replay.Value.TaskId);
        var changed = request.Clone();
        changed.Spec.Title = "other";
        Assert.Equal("command_id_reused", (await channel.Tasks.SubmitTaskAsync(changed, cancellationToken: Ct)).Error.Code);
        var second = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.Cmd, "/d", "/c", "exit 0"));
        await Tasks.WaitAsync(channel, first.Value.TaskId);
        await Tasks.WaitAsync(channel, second);
        var list = await channel.Tasks.ListTasksAsync(new TaskServiceListTasksRequest { Meta = Tasks.Meta() }, cancellationToken: Ct);
        Assert.Equal([second, first.Value.TaskId], list.Value.Tasks.Select(task => task.TaskId));
        var succeeded = await channel.Tasks.ListTasksAsync(new TaskServiceListTasksRequest
        {
            Meta = Tasks.Meta(),
            Filter = new TaskFilter { States = { TaskState.Succeeded } },
            Page = new PageRequest { Limit = 1 },
        }, cancellationToken: Ct);
        Assert.Single(succeeded.Value.Tasks);
        Assert.True(succeeded.Value.Page.HasMore);
    }

    [Fact(Timeout = 120_000)]
    public async Task AttachStreamsOutputThenTheResultAndWatchFollowsAnAttempt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var taskId = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "output", "--bytes", "300000", "--stream", "both", "--rate", "600000"));
        using var call = channel.Tasks.AttachTask(new TaskServiceAttachTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        var frames = new List<TaskServiceAttachTaskFrame>();
        while (await call.ResponseStream.MoveNext(Ct))
        {
            frames.Add(call.ResponseStream.Current);
        }

        Assert.Equal(TaskServiceAttachTaskFrame.FrameOneofCase.Started, frames[0].FrameCase);
        Assert.Equal(TaskServiceAttachTaskFrame.FrameOneofCase.Result, frames[^1].FrameCase);
        Assert.Equal(TerminationReason.Exited, frames[^1].Result.TerminationReason);
        var outputs = frames.Where(frame => frame.FrameCase == TaskServiceAttachTaskFrame.FrameOneofCase.Output).Select(frame => frame.Output).ToList();
        Assert.True(outputs.Count > 2, "Output arrived in several chunks while the task ran.");
        Assert.All(outputs, chunk => Assert.True(chunk.Data.Length <= 64 * 1024));
        Assert.Equal(300_000, outputs.Sum(chunk => chunk.Data.Length));

        var attempt = (await Tasks.GetAsync(channel, taskId)).CurrentAttempt.AttemptId;
        using var watch = channel.Tasks.WatchTaskOutput(new TaskServiceWatchTaskOutputRequest { Meta = Tasks.Meta(), AttemptId = attempt, Stream = OutputStream.Stdout, FromOffset = 1000 },
            cancellationToken: Ct);
        long watched = 0;
        TaskServiceWatchTaskOutputFrame? last = null;
        while (await watch.ResponseStream.MoveNext(Ct))
        {
            last = watch.ResponseStream.Current;
            watched += last.Output?.Data.Length ?? 0;
        }

        Assert.Equal(TaskServiceWatchTaskOutputFrame.FrameOneofCase.Result, last!.FrameCase);
        Assert.Equal(150_000 - 1000, watched);
        var wait = await channel.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest { Meta = Tasks.Meta(), TaskId = taskId, WaitMs = 100, TailBytes = 4096 }, cancellationToken: Ct);
        Assert.True(wait.Value.Reached);
        Assert.Equal(4096, wait.Value.Tail.Length);
        Assert.True(wait.Value.TailTruncated);
    }

    [Fact(Timeout = 120_000)]
    public async Task AFailedTaskCanBeRetriedPinnedAndItsRecordPurged()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var spec = Tasks.Argv(node.Root, Tasks.Cmd, "/d", "/c", "echo attempt & exit 3");
        spec.Environment.Set["API_TOKEN"] = "kept-for-retry";
        var taskId = await Tasks.SubmitAsync(channel, spec);
        var failed = await Tasks.WaitAsync(channel, taskId);
        Assert.Equal(TaskState.Failed, failed.State);

        var retry = await channel.Tasks.RetryTaskAsync(new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        Assert.Null(retry.Error);
        Assert.Contains(retry.Value.Warnings, warning => warning.Contains("unknown", StringComparison.OrdinalIgnoreCase));
        var again = await Tasks.WaitAsync(channel, taskId);
        Assert.Equal(2u, again.AttemptCount);
        var attempts = await channel.Tasks.ListAttemptsAsync(new TaskServiceListAttemptsRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        Assert.Equal([1u, 2u], attempts.Value.Attempts.Select(attempt => attempt.Number));
        var invalid = await channel.Tasks.RetryTaskAsync(new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = CommandIds.New() }, cancellationToken: Ct);
        Assert.Equal("not_found", invalid.Error.Code);

        Assert.Null((await channel.Tasks.PinTaskAsync(new TaskServicePinTaskRequest { Meta = Tasks.Meta(), TaskId = taskId, Pinned = true }, cancellationToken: Ct)).Error);
        Assert.True((await Tasks.GetAsync(channel, taskId)).Pinned);

        var directory = Tasks.Files(node, again.CurrentAttempt.AttemptId).Directory;
        Assert.True(Directory.Exists(directory));
        var purge = await channel.Tasks.PurgeTaskRecordAsync(new TaskServicePurgeTaskRecordRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        Assert.Null(purge.Error);
        Assert.False(Directory.Exists(directory));
        var afterPurge = await channel.Tasks.RetryTaskAsync(new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        Assert.Equal("not_found", afterPurge.Error.Code);

        // A script caller may not purge (tasks.proto: SCRIPT=D).
        await using var script = await node.ChannelAsync(helloAsHuman: false);
        var other = await Tasks.WaitAsync(script, await Tasks.SubmitAsync(script, Tasks.Argv(node.Root, Tasks.Cmd, "/d", "/c", "exit 0")));
        var denied = await script.Tasks.PurgeTaskRecordAsync(new TaskServicePurgeTaskRecordRequest { Meta = Tasks.Meta(), TaskId = other.TaskId }, cancellationToken: Ct);
        Assert.Equal("permission_denied", denied.Error.Code);
    }
}
