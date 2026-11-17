// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Mxc.Sdk.V1;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.MxcProbe.Linux;

// The fixture observations are untrusted. Native SDK outcomes, owned host-file
// comparisons and the enclosing driver's cgroup observations remain distinct.
[SupportedOSPlatform("linux")]
internal static partial class LinuxPolicyCases
{
    private static readonly byte[] FileSentinel = "AFV2_FILE_SENTINEL\n"u8.ToArray();
    private static readonly byte[] PersistenceSentinel = "AFV2_PERSISTENCE_SENTINEL\n"u8.ToArray();
    private static readonly string[] Roles = ["writable", "readonly", "control-denied", "neighbor", "outside"];
    private static readonly string[] Operations = ["read", "write"];
    private static readonly string[] FolderNames = ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "TMPDIR"];
    internal static LinuxSdkSession? UnresolvedCleanupOwner { get; private set; }

    internal static async Task<List<LinuxCaseResult>> RunAsync(string stage, string work, string control, LinuxEvidence log)
    {
        stage = Path.TrimEndingDirectorySeparator(Path.GetFullPath(stage));
        var cases = new List<LinuxCaseResult>();
        var steps = new Func<Task<LinuxCaseResult>>[]
        {
            () => BaselineAsync(work, control, log),
            () => FilesystemAsync(stage, work, control, log, "filesystem"),
            () => FilesystemAsync(stage, work, control, log, "directory-deny"),
            () => FilesystemAsync(stage, work, control, log, "file-deny"),
            () => FilesystemAsync(stage, work, control, log, "symlink-escape"),
            () => FilesystemAsync(stage, work, control, log, "external-grant"),
            () => EnvironmentAsync(stage, work, control, log),
            () => KnownFoldersAsync(stage, work, control, log),
            () => PersistenceAsync(stage, work, control, log),
            () => RejectionAsync(stage, work, control, log, "invalid-environment"),
            () => RejectionAsync(stage, work, control, log, "ingress-default-allow"),
            () => RejectionAsync(stage, work, control, log, "ingress-host-loopback-allow"),
        };
        foreach (var step in steps)
        {
            LinuxCaseResult result;
            try { result = await step().ConfigureAwait(false); }
            catch (Exception exception)
            {
                log.Failure("policy_fixture_setup", exception);
                result = new("policy_fixture_setup", false, new(StringComparer.Ordinal) { ["status"] = "partial" });
            }
            cases.Add(result);
            if (!result.Passed || UnresolvedCleanupOwner is not null) break;
        }
        return cases;
    }

    private static async Task<LinuxCaseResult> BaselineAsync(string work, string control, LinuxEvidence log)
    {
        var fixture = NewFixture(work, control, "baseline-reads");
        var request = LinuxRequestFactory.Create("/bin/sh", ["-c", "test -r /etc/os-release && test -r /bin/sh"], fixture.Data, fixture.Control, 10_000);
        return await ExecuteAsync("baseline-reads", request, fixture, log, _ => { }).ConfigureAwait(false);
    }

    private static async Task<LinuxCaseResult> FilesystemAsync(string stage, string work, string control, LinuxEvidence log, string variant)
    {
        var id = "policy-" + variant;
        var fixture = NewFixture(work, control, id);
        var readOnly = FreshDirectory(Path.Combine(fixture.Root, "readonly fixture"));
        var neighbor = FreshDirectory(Path.Combine(fixture.Root, "neighbor fixture"));
        var outside = FreshDirectory(Path.Combine(fixture.Root, "synthetic host home"));
        var external = FreshDirectory(Path.Combine(fixture.Root, "intentional host grant"));
        var writableFile = Seed(variant == "external-grant" ? external : fixture.Data);
        var readOnlyFile = Seed(readOnly);
        var controlFile = Seed(fixture.Control);
        var neighborFile = Seed(neighbor);
        var outsideFile = Seed(outside);
        if (variant == "symlink-escape")
        {
            log.Phase(id + "/symlink", "creating_owned_fixture");
            var link = Path.Combine(fixture.Data, "neighbor link");
            Directory.CreateSymbolicLink(link, neighbor);
            neighborFile = Path.Combine(link, "seed.txt");
        }
        string? denied = null;
        if (variant is "file-deny" or "directory-deny")
        {
            var deniedDirectory = FreshDirectory(Path.Combine(fixture.Data, "denied directory"));
            controlFile = Seed(deniedDirectory);
            denied = variant == "file-deny" ? controlFile : deniedDirectory;
        }
        var request = LinuxRequestFactory.Create(Path.Combine(stage, "arcforges-mxc-probe"),
            ["--linux-workload", "filesystem", writableFile, readOnlyFile, controlFile, neighborFile, outsideFile], fixture.Data, fixture.Control, 10_000);
        request.Filesystem!.ReadonlyPaths.Add(readOnly);
        request.Filesystem.DeniedPaths.Add(neighbor);
        if (denied is not null) request.Filesystem.DeniedPaths.Add(denied);
        if (variant == "external-grant") request.Filesystem.ReadwritePaths.Add(external);
        var protectedFiles = new[] { readOnlyFile, controlFile, Path.Combine(neighbor, "seed.txt"), outsideFile }.Distinct(StringComparer.Ordinal).ToArray();
        var before = protectedFiles.ToDictionary(path => path, FileHash, StringComparer.Ordinal);
        return await ExecuteAsync(id, request, fixture, log, rows =>
        {
            foreach (var role in Roles)
                foreach (var operation in Operations)
                {
                    var row = One(rows, "filesystem", item => item.GetProperty("role").GetString() == role
                        && item.GetProperty("operation").GetString() == operation);
                    var expected = role == "writable" || (role == "readonly" && operation == "read");
                    Require(row.GetProperty("succeeded").GetBoolean() == expected, "filesystem_effect_mismatch");
                    if (expected && operation == "read") Require(row.GetProperty("syntheticSentinel").GetBoolean(), "filesystem_seed_mismatch");
                }
            foreach (var item in before) Require(FileHash(item.Key) == item.Value, "protected_host_fixture_changed");
            Require(File.ReadAllBytes(writableFile).AsSpan().SequenceEqual([.. FileSentinel, .. FileSentinel]), "writable_fixture_effect_missing");
            log.Phase(id + "/host_files", "unchanged_protected_and_persisted_write", new(StringComparer.Ordinal)
            {
                ["protectedCount"] = before.Count.ToString(CultureInfo.InvariantCulture),
                ["writableSha256"] = FileHash(writableFile),
                ["grantOwnership"] = variant == "external-grant" ? "intentional_external_fixture_retained" : "sandbox_data",
            });
        }).ConfigureAwait(false);
    }

    private static async Task<LinuxCaseResult> EnvironmentAsync(string stage, string work, string control, LinuxEvidence log)
    {
        var fixture = NewFixture(work, control, "policy-clean-environment");
        var suffix = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture).ToUpperInvariant();
        var explicitName = "AFV2_MXC_EXPLICIT_" + suffix;
        var ambientName = "AFV2_MXC_AMBIENT_" + suffix;
        var explicitValue = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var ambientValue = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var request = LinuxRequestFactory.Create(Path.Combine(stage, "arcforges-mxc-probe"),
            ["--linux-workload", "environment", explicitName, ambientName], fixture.Data, fixture.Control, 10_000);
        request.Environment!.Add(explicitName, explicitValue);
        Environment.SetEnvironmentVariable(ambientName, ambientValue);
        try
        {
            return await ExecuteAsync("policy-clean-environment", request, fixture, log, rows =>
            {
                var supplied = One(rows, "environment", item => item.GetProperty("name").GetString() == explicitName);
                Require(supplied.GetProperty("present").GetBoolean(), "explicit_environment_missing");
                CheckDigest(supplied, explicitValue);
                var inherited = One(rows, "environment", item => item.GetProperty("name").GetString() == ambientName);
                Require(!inherited.GetProperty("present").GetBoolean(), "ambient_environment_inherited");
            }).ConfigureAwait(false);
        }
        finally { Environment.SetEnvironmentVariable(ambientName, null); }
    }

    private static async Task<LinuxCaseResult> KnownFoldersAsync(string stage, string work, string control, LinuxEvidence log)
    {
        var fixture = NewFixture(work, control, "policy-owned-folders");
        var request = LinuxRequestFactory.Create(Path.Combine(stage, "arcforges-mxc-probe"), ["--linux-workload", "known-folders"], fixture.Data, fixture.Control, 10_000);
        return await ExecuteAsync("policy-owned-folders", request, fixture, log, rows =>
        {
            foreach (var name in FolderNames)
            {
                var row = One(rows, "known-folder", item => item.GetProperty("name").GetString() == name);
                Require(row.GetProperty("present").GetBoolean(), "owned_folder_environment_missing");
                CheckDigest(row, request.Environment![name]);
            }
            var temp = One(rows, "known-folder", item => item.GetProperty("name").GetString() == "GetTempPath");
            CheckDigest(temp, Path.TrimEndingDirectorySeparator(request.Environment!["TMPDIR"]) + '/');
        }).ConfigureAwait(false);
    }

    private static async Task<LinuxCaseResult> PersistenceAsync(string stage, string work, string control, LinuxEvidence log)
    {
        const string id = "policy-persistent-sandbox";
        var fixture = NewFixture(work, control, id);
        var path = Path.Combine(fixture.Data, "persistent state.txt");
        var write = LinuxRequestFactory.Create(Path.Combine(stage, "arcforges-mxc-probe"), ["--linux-workload", "persistence", "write", path], fixture.Data, fixture.Control, 10_000);
        var written = await ExecuteAsync(id + "-first-run", write, fixture, log, rows =>
        {
            var row = One(rows, "persistence", item => item.GetProperty("operation").GetString() == "write");
            Require(row.GetProperty("succeeded").GetBoolean() && File.ReadAllBytes(path).AsSpan().SequenceEqual(PersistenceSentinel), "persistent_write_missing");
        }).ConfigureAwait(false);
        if (!written.Passed || UnresolvedCleanupOwner is not null) return written;
        // The first SDK owner is fully disposed. Only Sandbox data persists.
        var hash = FileHash(path);
        log.Phase(id + "/observations_archive", "begin");
        var observations = LinuxRequestFactory.OwnedDirectory(Path.Combine(fixture.Data, "observations"));
        var archive = Path.Combine(fixture.Control, "first-run-observations");
        Require(!Directory.Exists(archive) && !File.Exists(archive), "persistence_observation_archive_collision");
        Directory.Move(observations, archive);
        log.Phase(id + "/observations_archive", "retained_outside_second_run_grant");
        var read = LinuxRequestFactory.Create(Path.Combine(stage, "arcforges-mxc-probe"), ["--linux-workload", "persistence", "read", path], fixture.Data, fixture.Control, 10_000);
        var result = await ExecuteAsync(id + "-second-run", read, fixture, log, rows =>
        {
            var row = One(rows, "persistence", item => item.GetProperty("operation").GetString() == "read");
            Require(row.GetProperty("succeeded").GetBoolean() && FileHash(path) == hash, "persistent_read_missing");
        }).ConfigureAwait(false);
        result.Facts["firstRunCleaned"] = "true";
        result.Facts["persistentFileSha256"] = hash;
        return result;
    }

    private static async Task<LinuxCaseResult> RejectionAsync(string stage, string work, string control, LinuxEvidence log, string variant)
    {
        var id = "policy-reject-" + variant;
        var fixture = NewFixture(work, control, id);
        var entry = Path.Combine(fixture.Data, "must-not-enter.txt");
        var request = LinuxRequestFactory.Create(Path.Combine(stage, "arcforges-mxc-probe"), ["--linux-workload", "persistence", "write", entry], fixture.Data, fixture.Control, 10_000);
        if (variant == "invalid-environment") request.Environment!.Add("", "synthetic-invalid-key");
        else if (variant == "ingress-default-allow") request.Network!.Ingress!.Default = NetworkAction.Allow;
        else request.Network!.Ingress!.HostLoopback = NetworkAction.Allow;
        LinuxSdkSession? session = null;
        var rejected = false;
        var facts = new Dictionary<string, string>(StringComparer.Ordinal) { ["payloadStarted"] = "UNKNOWN", ["status"] = "partial" };
        log.Phase(id + "/spawn", "attempting_invalid_request");
        try
        {
            session = LinuxSdkSession.Start(request, false, log, id.Replace('-', '_'));
            throw new LinuxProbeException("invalid_request_returned_live_session");
        }
        catch (MxcException exception) when (exception.Code is ErrorCode.MalformedRequest or ErrorCode.PolicyValidation)
        {
            log.Failure(id + "/expected_rejection", exception);
            facts["sdkCode"] = exception.Code.ToString();
            facts["sdkCodeValue"] = ((int)exception.Code).ToString(CultureInfo.InvariantCulture);
            facts["refusalSource"] = "official_sdk_structured_admission_error";
            rejected = true;
        }
        catch (ArgumentException exception) when (variant == "invalid-environment" && session is null)
        {
            log.Failure(id + "/expected_rejection", exception);
            facts["refusalSource"] = "public_sdk_argument_validation";
            rejected = true;
        }
        catch (LinuxSdkLaunchException exception)
        {
            UnresolvedCleanupOwner = exception.CleanupOwner;
            log.Failure(id + "/launch_cleanup", exception, cleanup: true);
        }
        catch (Exception exception) { log.Failure(id + "/unexpected_failure", exception); }
        finally
        {
            if (session is not null)
            {
                try { await session.DisposeAsync().ConfigureAwait(false); log.Phase(id + "/cleanup", "sdk_owner_disposed"); }
                catch (Exception exception) { UnresolvedCleanupOwner = session; log.Failure(id + "/cleanup", exception, cleanup: true); rejected = false; }
            }
            else log.Phase(id + "/cleanup", UnresolvedCleanupOwner is null ? "no_sdk_session_returned" : "owner_retained_unresolved");
        }
        try
        {
            var observations = ReadObservations(fixture.Data, log, id);
            Require(rejected && !File.Exists(entry) && observations.Length == 0 && UnresolvedCleanupOwner is null, "invalid_request_refusal_not_proven");
            facts["entryFileAbsent"] = "true";
            facts["fixtureEvents"] = "0";
            facts["payloadStarted"] = "NOT_STARTED";
            facts["boundary"] = "structured_prelaunch_rejection_not_stderr_or_exit_inference";
            log.Phase(id + "/assertions", "passed", facts);
        }
        catch (Exception exception) { log.Failure(id + "/assertions", exception); rejected = false; }
        return new(id, rejected, facts);
    }

    private static async Task<LinuxCaseResult> ExecuteAsync(string id, ContainerRequest request, Fixture fixture, LinuxEvidence log, Action<JsonElement[]> verify)
    {
        LinuxSdkSession? session = null;
        var passed = false;
        var facts = new Dictionary<string, string>(StringComparer.Ordinal) { ["status"] = "partial", ["exitSource"] = "unknown" };
        log.Phase(id + "/start", "prepared", new(StringComparer.Ordinal) { ["backend"] = "Bubblewrap", ["terminal"] = "false" });
        try
        {
            session = LinuxSdkSession.Start(request, false, log, id.Replace('-', '_'));
            facts["sdkProcessId"] = session.ProcessId.ToString(CultureInfo.InvariantCulture);
            var exit = await session.WaitAsync(TimeSpan.FromSeconds(20)).ConfigureAwait(false);
            facts["exitCode"] = exit.ExitCode.ToString(CultureInfo.InvariantCulture);
            facts["exitSource"] = exit.ExitSource;
            facts["nativeProcessAbsent"] = exit.NativeProcessAbsent.ToString(CultureInfo.InvariantCulture);
            facts["stdoutBytes"] = exit.StdoutBytes.ToString(CultureInfo.InvariantCulture);
            facts["stderrBytes"] = exit.StderrBytes.ToString(CultureInfo.InvariantCulture);
            log.Phase(id + "/wait", "returned", facts);
            Require(exit.ExitCode == 0 && !exit.TimedOut && exit.Drained && exit.NativeProcessAbsent, "policy_fixture_native_execution_failed");
            var observations = ReadObservations(fixture.Data, log, id);
            Require(observations.Where(row => row.GetProperty("event").GetString() == "cleanup")
                .All(row => row.GetProperty("succeeded").GetBoolean()), "fixture_native_cleanup_failed");
            verify(observations);
            passed = true;
            log.Phase(id + "/assertions", "passed");
        }
        catch (LinuxSdkLaunchException exception)
        {
            UnresolvedCleanupOwner = exception.CleanupOwner;
            log.Failure(id + "/launch_cleanup", exception, cleanup: true);
        }
        catch (Exception exception) { log.Failure(id + "/execution", exception); }
        finally
        {
            if (session is not null)
            {
                try { await session.DisposeAsync().ConfigureAwait(false); facts["sdkOwnerDisposed"] = "true"; log.Phase(id + "/cleanup", "sdk_owner_disposed"); }
                catch (Exception exception)
                {
                    passed = false;
                    UnresolvedCleanupOwner = session;
                    log.Failure(id + "/cleanup", exception, cleanup: true);
                }
            }
            else log.Phase(id + "/cleanup", UnresolvedCleanupOwner is null ? "no_sdk_session_returned" : "owner_retained_unresolved");
        }
        // SDK process absence is not cgroup emptiness; the owner/driver checks
        // the outer boundary and helpers separately before final qualification.
        return new(id, passed && UnresolvedCleanupOwner is null, facts);
    }

    private static JsonElement[] ReadObservations(string data, LinuxEvidence log, string id)
    {
        const int perFileLimit = 65_536;
        const int totalLimit = 1_048_576;
        var directory = LinuxRequestFactory.OwnedDirectory(Path.Combine(data, "observations"));
        // Pin the directory and open members relative to that descriptor. A
        // payload cannot turn a checked path into a host symlink read between
        // the path check and open. NONBLOCK also refuses to hang on a FIFO.
        var descriptor = OpenDirectory(directory, 0x80000 | 0x20000 | 0x10000);
        if (descriptor < 0) throw new Win32Exception(Marshal.GetLastPInvokeError(), "open_owned_observation_directory");
        using var directoryHandle = new SafeFileHandle(descriptor, ownsHandle: true);
        var pinned = "/proc/self/fd/" + descriptor.ToString(CultureInfo.InvariantCulture);
        var files = Directory.GetFiles(pinned);
        Require(files.Length <= 16 && !Directory.EnumerateDirectories(pinned).Any(), "fixture_observation_file_bound");
        var rows = new List<JsonElement>();
        var total = 0L;
        foreach (var path in files.Order(StringComparer.Ordinal))
        {
            var name = Path.GetFileNameWithoutExtension(path);
            Require(Path.GetExtension(path) == ".jsonl" && name.Length <= 10 && name.All(char.IsAsciiDigit)
                && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, "fixture_observation_path_invalid");
            var fileDescriptor = OpenMember(descriptor, Path.GetFileName(path), 0x80000 | 0x20000 | 0x800);
            if (fileDescriptor < 0) throw new Win32Exception(Marshal.GetLastPInvokeError(), "open_owned_observation_member");
            using var fileHandle = new SafeFileHandle(fileDescriptor, ownsHandle: true);
            using var input = new FileStream(fileHandle, FileAccess.Read);
            total += input.Length;
            Require(input.Length <= perFileLimit && total <= totalLimit, "fixture_observation_byte_bound");
            var bytes = new byte[checked((int)input.Length)];
            input.ReadExactly(bytes);
            Require(bytes.Length == 0 || bytes[^1] == (byte)'\n', "fixture_observation_incomplete_record");
            foreach (var line in new UTF8Encoding(false, true).GetString(bytes).Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 16 });
                Require(document.RootElement.GetProperty("fixture").GetString() == "linux-workload-v1", "fixture_observation_identity_invalid");
                rows.Add(document.RootElement.Clone());
            }
            log.Phase(id + "/observation", "untrusted_fixture_file", new(StringComparer.Ordinal)
            {
                ["file"] = Path.GetFileName(path),
                ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(bytes)),
                ["bytes"] = bytes.Length.ToString(CultureInfo.InvariantCulture),
            });
        }
        return [.. rows];
    }

    private static JsonElement One(JsonElement[] rows, string name, Func<JsonElement, bool> predicate)
    {
        var matches = rows.Where(row => row.GetProperty("event").GetString() == name && predicate(row)).ToArray();
        Require(matches.Length == 1, "fixture_observation_missing_or_ambiguous");
        return matches[0];
    }

    private static void CheckDigest(JsonElement item, string expected)
    {
        var bytes = Encoding.UTF8.GetBytes(expected);
        Require(item.GetProperty("length").GetInt32() == expected.Length && item.GetProperty("utf8Bytes").GetInt32() == bytes.Length
            && item.GetProperty("sha256").GetString() == Convert.ToHexStringLower(SHA256.HashData(bytes)), "fixture_digest_mismatch");
    }

    private sealed record Fixture(string Root, string Data, string Control);

    private static Fixture NewFixture(string work, string control, string id)
    {
        var root = FreshDirectory(Path.Combine(work, id));
        var data = FreshDirectory(Path.Combine(root, "sandbox data"));
        var privateControl = FreshDirectory(Path.Combine(control, id));
        return new(root, data, privateControl);
    }

    private static string FreshDirectory(string path)
    {
        var full = Path.GetFullPath(path);
        if (Directory.Exists(full) || File.Exists(full)) throw new LinuxProbeException("policy_fixture_directory_collision");
        Directory.CreateDirectory(full, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return LinuxRequestFactory.OwnedDirectory(full);
    }

    private static string Seed(string directory)
    {
        var path = Path.Combine(directory, "seed.txt");
        using var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.Read,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
        stream.Write(FileSentinel);
        stream.Flush(flushToDisk: true);
        return path;
    }

    private static string FileHash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static void Require(bool value, string code)
    {
        if (!value) throw new LinuxProbeException(code);
    }

    [LibraryImport("libc", EntryPoint = "open", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int OpenDirectory(string path, int flags);

    [LibraryImport("libc", EntryPoint = "openat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int OpenMember(int directory, string name, int flags);
}
