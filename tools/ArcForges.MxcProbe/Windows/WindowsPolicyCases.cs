// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.MxcProbe;

// Bounded WIN-01 / filesystem portions of WIN-04. Network endpoints and the
// cross-protocol combination remain with their explicit owning cases.
[SupportedOSPlatform("windows")]
internal static partial class WindowsPolicyCases
{
    private static readonly byte[] FileSentinel = "AFV2_FILE_SENTINEL\n"u8.ToArray();
    private static readonly string[] KnownFolderNames = ["UserProfile", "ApplicationData", "LocalApplicationData"];
    private static readonly string[] FilesystemRoles = ["writable", "readonly", "control-denied", "neighbor", "outside"];
    private static readonly string[] FilesystemOperations = ["read", "write"];
    // Preserve the exact parser-process handle if its bounded cleanup ever fails.
    internal static Process? UnresolvedMissingPolicyProcess { get; private set; }

    internal static async Task<List<WindowsQualificationCase>> RunAsync(string stage, string work)
    {
        var cases = new List<WindowsQualificationCase>();
        var steps = new Func<Task<WindowsQualificationCase>>[]
        {
            () => ArgumentsAsync(stage, work),
            () => EnvironmentAsync(stage, work),
            () => KnownFoldersAsync(stage, work),
            () => FilesystemAsync(stage, work, "filesystem-policy", reparse: false, externalGrant: false),
            () => FilesystemAsync(stage, work, "filesystem-reparse", reparse: true, externalGrant: false),
            () => FilesystemAsync(stage, work, "filesystem-external-grant", reparse: false, externalGrant: true),
            () => RejectionAsync(stage, work, "malformed"),
            () => RejectionAsync(stage, work, "schema-version"),
            () => MissingPolicyAsync(stage, work),
            () => RejectionAsync(stage, work, "invalid-environment"),
            () => RejectionAsync(stage, work, "least-privilege"),
            () => RejectionAsync(stage, work, "proxy-peer-without-proxy"),
        };
        foreach (var step in steps)
        {
            WindowsQualificationCase result;
            try { result = await step().ConfigureAwait(false); }
            catch (Exception exception)
            {
                result = new WindowsQualificationCase { Name = "policy-fixture-setup", Protocol = "MXC-WIN-01" };
                Fail(result, exception);
            }
            cases.Add(result);
            // A failed case needs diagnosis; no further payloads are started by this slice.
            if (!result.Passed || result.UnresolvedCleanupOwner is not null) break;
        }
        return cases;
    }

    private static async Task<WindowsQualificationCase> ArgumentsAsync(string stage, string work)
    {
        string[] values = ["", "two words", "embedded\"quote", "trailing\\", "two trailing\\\\", "星 Ω 😀", "&|<>^%!", "a\\\"b"];
        var fixture = CreateFixture(stage, work, "argv-roundtrip", ["argv", .. values]);
        var privateFileContract = VerifyPolicyFileContract(fixture.Policy);
        var result = await WindowsQualification.RunCaseAsync("argv-roundtrip", stage, fixture.Policy, async (_, capture) =>
        {
            var count = await capture.WaitForEventAsync("argv-count", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            Check(count.GetProperty("count").GetInt32() == values.Length, "argv_count_mismatch");
            for (var index = 0; index < values.Length; index++)
            {
                var expectedIndex = index;
                var item = await capture.WaitForEventAsync("argv", TimeSpan.FromSeconds(5), x => x.GetProperty("index").GetInt32() == expectedIndex).ConfigureAwait(false);
                CheckDigest(item, values[index], "argv_digest_mismatch");
            }
        }, fixtureEventsDirectory: fixture.EventsDirectory).ConfigureAwait(false);
        result.Protocol = "MXC-WIN-01";
        Evidence(result, fixture.Policy.ControlDirectory, "private-policy-creation.json", writer =>
        {
            writer.WriteBoolean("existingControlRejected", privateFileContract.ExistingControlRejected);
            writer.WriteBoolean("createNewCollisionRejected", privateFileContract.CreateNewRejected);
            writer.WriteBoolean("replacementWhileReadLeaseRejected", privateFileContract.ReplacementRejected);
            writer.WriteBoolean("deletionWhileReadLeaseRejected", privateFileContract.DeletionRejected);
            writer.WriteString("policySha256Unchanged", fixture.Policy.Sha256);
            writer.WriteString("leaseScope", "The deliberate owner read lease covers only these actual replacement attempts and ends before launch. ConPtySession separately leases through its Start call; no post-return or official-consumption-time lease is claimed.");
        });
        CheckAcls(result, fixture);
        return result;
    }

    private static async Task<WindowsQualificationCase> EnvironmentAsync(string stage, string work)
    {
        var suffix = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture).ToUpperInvariant();
        var explicitName = "AFV2_MXC_EXPLICIT_" + suffix;
        var ambientName = "AFV2_MXC_AMBIENT_" + suffix;
        var explicitValue = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var ambientValue = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var fixture = CreateFixture(stage, work, "clean-environment", ["environment", explicitName, ambientName], request =>
            request.Process.Env = [.. request.Process.Env, explicitName + "=" + explicitValue]);
        Environment.SetEnvironmentVariable(ambientName, ambientValue);
        WindowsQualificationCase result;
        try
        {
            result = await WindowsQualification.RunCaseAsync("clean-environment", stage, fixture.Policy, async (_, capture) =>
            {
                var supplied = await capture.WaitForEventAsync("environment", TimeSpan.FromSeconds(5), x => x.GetProperty("name").GetString() == explicitName).ConfigureAwait(false);
                Check(supplied.GetProperty("present").GetBoolean(), "explicit_environment_missing");
                CheckDigest(supplied, explicitValue, "explicit_environment_digest_mismatch");
                var inherited = await capture.WaitForEventAsync("environment", TimeSpan.FromSeconds(5), x => x.GetProperty("name").GetString() == ambientName).ConfigureAwait(false);
                Check(!inherited.GetProperty("present").GetBoolean(), "ambient_environment_inherited");
                Check(!capture.Contains(explicitValue) && !capture.Contains(ambientValue), "synthetic_environment_in_output");
            }, fixtureEventsDirectory: fixture.EventsDirectory).ConfigureAwait(false);
        }
        finally { Environment.SetEnvironmentVariable(ambientName, null); }
        result.Protocol = "MXC-WIN-04";
        CheckAcls(result, fixture);
        return result;
    }

    private static async Task<WindowsQualificationCase> KnownFoldersAsync(string stage, string work)
    {
        var fixture = CreateFixture(stage, work, "known-folder-observations", ["known-folders"]);
        var observations = new List<JsonElement>();
        var expected = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["HOME"] = fixture.Owned.Home, ["USERPROFILE"] = fixture.Owned.Home,
            ["APPDATA"] = fixture.Owned.Config,
        };
        var result = await WindowsQualification.RunCaseAsync("known-folder-observations", stage, fixture.Policy, async (_, capture) =>
        {
            foreach (var item in expected)
            {
                var row = await capture.WaitForEventAsync("known-folder", TimeSpan.FromSeconds(5), x => x.GetProperty("source").GetString() == "environment"
                    && x.GetProperty("name").GetString() == item.Key).ConfigureAwait(false);
                Check(row.GetProperty("present").GetBoolean(), "owned_folder_environment_missing");
                CheckDigest(row, item.Value, "owned_folder_environment_mismatch");
                observations.Add(row);
            }
            // PSEC may redirect LOCALAPPDATA and TEMP/TMP below the explicit
            // owned cache. Require the actual values to remain inside that
            // root, and bind each bounded relative-path observation to its hash.
            var local = await capture.WaitForEventAsync("known-folder", TimeSpan.FromSeconds(5), x => x.GetProperty("source").GetString() == "environment"
                && x.GetProperty("name").GetString() == "LOCALAPPDATA").ConfigureAwait(false);
            OwnedCacheValue(local, fixture.Owned.Cache);
            observations.Add(local);
            var temp = await capture.WaitForEventAsync("known-folder", TimeSpan.FromSeconds(5), x => x.GetProperty("source").GetString() == "environment"
                && x.GetProperty("name").GetString() == "TEMP").ConfigureAwait(false);
            var tempPath = OwnedCacheValue(temp, fixture.Owned.Cache);
            observations.Add(temp);
            var tmp = await capture.WaitForEventAsync("known-folder", TimeSpan.FromSeconds(5), x => x.GetProperty("source").GetString() == "environment"
                && x.GetProperty("name").GetString() == "TMP").ConfigureAwait(false);
            Check(OwnedCacheValue(tmp, fixture.Owned.Cache).Equals(tempPath, StringComparison.Ordinal), "owned_temp_environment_disagreement");
            observations.Add(tmp);
            foreach (var name in KnownFolderNames)
                observations.Add(await capture.WaitForEventAsync("known-folder", TimeSpan.FromSeconds(5), x => x.GetProperty("source").GetString() == "special-folder"
                    && x.GetProperty("name").GetString() == name).ConfigureAwait(false));
            var temporary = await capture.WaitForEventAsync("known-folder", TimeSpan.FromSeconds(5), x => x.GetProperty("source").GetString() == "path").ConfigureAwait(false);
            Check(temporary.GetProperty("underOwnedCache").GetBoolean(), "temp_api_escaped_owned_cache");
            CheckDigest(temporary, Path.TrimEndingDirectorySeparator(tempPath) + Path.DirectorySeparatorChar, "owned_temp_api_mismatch");
            observations.Add(temporary);
        }, fixtureEventsDirectory: fixture.EventsDirectory).ConfigureAwait(false);
        result.Protocol = "MXC-WIN-04";
        Evidence(result, fixture.Policy.ControlDirectory, "known-folders.json", writer =>
        {
            writer.WriteString("scope", "HOME/USERPROFILE/APPDATA are exact requested owned paths. PSEC-redirection observations for LOCALAPPDATA/TEMP/TMP must reconstruct inside the explicit owned cache; TEMP/TMP agree and GetTempPath matches TEMP. Windows known-folder API hashes remain observations, not a promise of API redirection.");
            writer.WriteStartArray("observations");
            foreach (var row in observations) row.WriteTo(writer);
            writer.WriteEndArray();
        });
        CheckAcls(result, fixture);
        return result;
    }

    private static string OwnedCacheValue(JsonElement row, string ownedCache)
    {
        Check(row.GetProperty("present").GetBoolean() && row.GetProperty("underOwnedCache").GetBoolean(), "folder_environment_escaped_owned_cache");
        var relative = row.GetProperty("ownedCacheRelativePath").GetString();
        Check(relative is not null && relative.Length <= 4096 && !Path.IsPathRooted(relative)
            && !relative.Contains(':', StringComparison.Ordinal) && !relative.Contains('\0', StringComparison.Ordinal), "owned_cache_relative_path_invalid");
        var root = Path.GetFullPath(ownedCache);
        var value = Path.GetFullPath(Path.Combine(root, relative!));
        Check(value.Equals(root, StringComparison.OrdinalIgnoreCase)
            || value.StartsWith(Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase), "folder_environment_escaped_owned_cache");
        CheckDigest(row, value, "owned_cache_observation_digest_mismatch");
        return value;
    }

    private static async Task<WindowsQualificationCase> FilesystemAsync(string stage, string work, string name, bool reparse, bool externalGrant)
    {
        var root = NewRoot(work, name);
        var owned = CreateOwned(root);
        var control = Path.Combine(root, "private control");
        var readOnly = Path.Combine(root, "readonly fixture");
        var neighbor = Path.Combine(root, "neighbor fixture");
        var outside = Path.Combine(root, "ungranted fixture");
        var external = Path.Combine(root, "external host-owned fixture");
        foreach (var path in new[] { readOnly, neighbor, outside, external }) Directory.CreateDirectory(path);
        var readOnlyFile = Seed(readOnly);
        var neighborFile = Seed(neighbor);
        var outsideFile = Seed(outside);
        var writableFile = Path.Combine(externalGrant ? external : owned.Work, "written.txt");
        var alias = Path.Combine(owned.Work, "neighbor junction");
        if (reparse) CreateJunction(alias, neighbor);
        var observedNeighbor = reparse ? Path.Combine(alias, "seed.txt") : neighborFile;
        var controlFile = Path.Combine(control, "request.json");
        var request = WindowsPolicy.BuildRequest(Path.Combine(stage, "arcforges-mxc-probe.exe"),
            ["--windows-workload", "filesystem", writableFile, readOnlyFile, controlFile, observedNeighbor, outsideFile], owned,
            [stage, Environment.SystemDirectory, readOnly], [control, neighbor], WindowsNetworkChoice.DenyAll);
        if (externalGrant) request.Filesystem.ReadwritePaths = [.. request.Filesystem.ReadwritePaths, external];
        var events = WindowsQualification.EnableFixtureEvents(request, owned.Work);
        var policy = WindowsPolicy.WritePrivate(control, request);
        var snapshots = FixtureSnapshots(owned, policy, [readOnly, neighbor, outside, external, readOnlyFile, neighborFile, outsideFile]);
        var beforeFiles = new[] { readOnlyFile, neighborFile, outsideFile }.Select(HashFile).ToArray();
        var hostGuardRejected = false;
        if (reparse)
        {
            var target = Path.Combine(root, "host private-parent target");
            Directory.CreateDirectory(target);
            var parentAlias = Path.Combine(root, "host private-parent junction");
            CreateJunction(parentAlias, target);
            try { WindowsPolicy.CreatePrivateControl(Path.Combine(parentAlias, "must-not-create")); }
            catch (InvalidDataException) { hostGuardRejected = true; }
            Check(hostGuardRejected && !Directory.Exists(Path.Combine(target, "must-not-create")), "control_reparse_parent_not_refused");
        }
        var result = await WindowsQualification.RunCaseAsync(name, stage, policy, async (_, capture) =>
        {
            foreach (var role in FilesystemRoles)
            foreach (var operation in FilesystemOperations)
            {
                var expected = role == "writable" || role == "readonly" && operation == "read";
                var row = await capture.WaitForEventAsync("filesystem", TimeSpan.FromSeconds(5), x => x.GetProperty("role").GetString() == role
                    && x.GetProperty("operation").GetString() == operation).ConfigureAwait(false);
                Check(row.GetProperty("succeeded").GetBoolean() == expected, "filesystem_effect_mismatch");
                if (expected && operation == "read") Check(row.GetProperty("syntheticSentinel").GetBoolean(), "filesystem_readback_mismatch");
            }
        }, fixtureEventsDirectory: events).ConfigureAwait(false);
        result.Protocol = "MXC-WIN-04";
        try
        {
            Check(File.ReadAllBytes(writableFile).AsSpan().SequenceEqual(FileSentinel), "owned_file_write_not_observed");
            Check(new[] { readOnlyFile, neighborFile, outsideFile }.Select(HashFile).SequenceEqual(beforeFiles), "denied_or_readonly_host_file_changed");
            Check(HashFile(controlFile) == policy.Sha256, "private_policy_changed");
        }
        catch (Exception exception) { Fail(result, exception); }
        Evidence(result, policy.ControlDirectory, "filesystem-observations.json", writer =>
        {
            writer.WriteBoolean("reparseAttempt", reparse);
            writer.WriteBoolean("hostPrivateParentReparseRejected", hostGuardRejected);
            writer.WriteBoolean("explicitExternalGrant", externalGrant);
            writer.WriteString("externalFixtureLifetime", "Host-owned fixture retained; this runner never deletes it as Sandbox data.");
        });
        CheckAcls(result, new Fixture(owned, policy, snapshots, events));
        return result;
    }

    private static async Task<WindowsQualificationCase> RejectionAsync(string stage, string work, string variant)
    {
        var name = "reject-" + variant;
        var root = NewRoot(work, name);
        var owned = CreateOwned(root);
        var control = Path.Combine(root, "private control");
        var entry = Path.Combine(owned.Work, "payload-entry.txt");
        var seed = Seed(owned.Data);
        var request = WindowsPolicy.BuildRequest(Path.Combine(stage, "arcforges-mxc-probe.exe"),
            ["--windows-workload", "filesystem", entry, seed, Path.Combine(control, "request.json"), seed, seed], owned,
            [stage, Environment.SystemDirectory], [control], WindowsNetworkChoice.DenyAll);
        switch (variant)
        {
            case "schema-version": request.Version = "0.0.0-unapproved"; break;
            case "invalid-environment": request.Process.Env = [.. request.Process.Env, "AFV2_MXC_BAD\0KEY=value"]; break;
            case "least-privilege": request.ProcessContainer.LeastPrivilege = true; break;
            case "proxy-peer-without-proxy":
                request.ProcessContainer.Network = new WindowsPolicyProcessContainerNetwork { AllowedProxyPeer = "127.0.0.1" };
                break;
        }
        var events = WindowsQualification.EnableFixtureEvents(request, owned.Work);
        var policy = variant == "malformed" ? MalformedPolicy(control) : WindowsPolicy.WritePrivate(control, request);
        var fixture = new Fixture(owned, policy, FixtureSnapshots(owned, policy, [seed]), events);
        var result = new WindowsQualificationCase { Name = name, Protocol = "MXC-WIN-01", PolicySha256 = policy.Sha256 };
        var watch = Stopwatch.StartNew();
        ConPtySession? session = null;
        WindowsTerminalCapture? capture = null;
        var officialCreateProcessRefused = false;
        try
        {
            // A probe failure alone cannot pass this case: launch the pinned official executor.
            session = ConPtySession.Start(new(Path.Combine(stage, "wxc-exec.exe"), policy.Path, control, 80, 24, new(5000, 1024UL * 1024 * 1024, 16),
                PrivateDiagnostics: variant == "invalid-environment"));
            result.ExecutorProcessId = session.ProcessId;
            result.ExecutorStartUtc = session.ProcessStartTimeUtc.ToString("O", CultureInfo.InvariantCulture);
            result.InheritedJob = session.InheritedJob;
            result.SpawnMs = session.SpawnMs;
            capture = new WindowsTerminalCapture(session, control, events);
            var exited = await session.WaitAsync(TimeSpan.FromSeconds(20)).ConfigureAwait(false);
            capture.Refresh();
            result.RawExecutorExit = exited.RawExitCode;
            result.ExitSource = exited.ExitSource;
            result.JobEmpty = exited.JobEmpty;
            result.FinalJob = exited.Job;
            Check(exited.ExitSource == "official_executor" && exited.JobEmpty, "refusal_exit_or_job_cleanup_missing");
            Check(!File.Exists(entry), "rejected_policy_entered_payload");
            Check(WindowsTerminalCapture.ReadFixtureEvents(events).Length == 0, "rejected_policy_emitted_payload_event");
            Check(capture.ObservedBytes > 0 && capture.DrainFailure is null, "official_refusal_diagnostics_missing");
            Check(!capture.Contains("script timed out"), "execution_timeout_is_not_policy_refusal");
            if (variant == "invalid-environment")
            {
                VerifyInvalidEnvironmentRefusal(result, session, control, owned.Work, exited);
                officialCreateProcessRefused = true;
            }
            else Check(exited.RawExitCode != 0 && (exited.RawExitCode & 0x80000000) == 0, "refusal_was_success_or_native_startup_crash");
            result.Passed = true;
        }
        catch (ConPtyLaunchException exception)
        {
            if (exception.InnerException is AggregateException combined && combined.InnerExceptions.Count >= 2)
            {
                Fail(result, combined.InnerExceptions[0]);
                result.CleanupFailure = WindowsQualification.ObserveFailure(combined.InnerExceptions[1]);
            }
            else { Fail(result, exception); }
            result.UnresolvedCleanupOwner = exception.CleanupOwner;
        }
        catch (Exception exception) { Fail(result, exception); }
        finally
        {
            if (session is not null)
            {
                try { await session.DisposeAsync().ConfigureAwait(false); result.CleanupCompleted = true; }
                catch (Exception exception)
                {
                    result.CleanupFailure = WindowsQualification.ObserveFailure(exception);
                    result.UnresolvedCleanupOwner = session;
                    result.Passed = false;
                }
            }
            if (capture is not null)
            {
                try
                {
                    capture.Refresh();
                    result.ObservedTerminalBytes = capture.ObservedBytes;
                    result.CapturedBytes = capture.CapturedBytes;
                    result.CaptureTruncated = capture.CaptureTruncated;
                    result.ReplayGaps = capture.Gaps;
                    result.DrainFailure = capture.DrainFailure;
                    var transcript = Path.Combine(control, "terminal.bin");
                    await capture.WritePrivateTranscriptAsync(transcript).ConfigureAwait(false);
                    result.PrivateTranscriptFile = "terminal.bin";
                    result.PrivateTranscriptSha256 = capture.Sha256();
                }
                catch (Exception exception) { result.EvidenceFailure = WindowsQualification.ObserveFailure(exception); result.Passed = false; }
                finally { capture.Dispose(); }
            }
            result.ElapsedMs = watch.Elapsed.TotalMilliseconds;
        }
        Evidence(result, control, "refusal-observations.json", writer =>
        {
            writer.WriteString("variant", variant);
            writer.WriteBoolean("entryFileAbsent", !File.Exists(entry));
            writer.WriteBoolean("officialCreateProcessRefused", officialCreateProcessRefused);
            writer.WriteString("scope", "Actual official executor refusal before the controlled entry marker. Invalid environment requires its owner-private official diagnostic, exact CreateProcessW error 87, structured error-envelope agreement and an outer Job containing only the executor; payload stdout and marker absence alone are not authority.");
        });
        CheckAcls(result, fixture);
        return result;
    }

    private static void VerifyInvalidEnvironmentRefusal(WindowsQualificationCase result, ConPtySession session, string control, string work, ConPtyExit exited)
    {
        // The pinned executor explicitly returns ScriptResponse.exit_code = -1
        // for this failed native CreateProcessW call. It is not a payload exit
        // or a startup-crash classification merely because its high bit is set.
        Check(exited.RawExitCode == uint.MaxValue && exited.Job is { TotalProcesses: 1, ActiveProcesses: 0 }
            && exited.Job.ProcessIds.Length == 0, "invalid_environment_native_refusal_not_proven");
        var path = Path.Combine(control, "executor-diagnostic.log");
        WindowsPolicy.VerifyPrivateFile(path);
        using var input = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Check(input.Length is > 0 and <= WindowsPolicy.MaximumUtf8Bytes, "official_refusal_diagnostic_bound");
        var bytes = new byte[checked((int)input.Length)];
        input.ReadExactly(bytes);
        var diagnostic = RemoveOfficialLogTimestamps(new UTF8Encoding(false, true).GetString(bytes));
        var extended = "CreateProcessW(PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT) failed: WIN32_ERROR(87) (working directory: " + work + " (from process.cwd))";
        const string message = "CreateProcessW failed with error code 87 (0x00000057).";
        Check(diagnostic.Contains("Error: " + extended, StringComparison.Ordinal)
            && diagnostic.Contains("Error: Launch diagnostic [create_process_failed]: " + message, StringComparison.Ordinal)
            && !diagnostic.Contains("process created (PID:", StringComparison.Ordinal), "official_private_create_process_refusal_missing");
        var policyAudit = false;
        foreach (var line in diagnostic.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!line.StartsWith("{\"event\":\"mxc.PolicyHash\",", StringComparison.Ordinal)) continue;
            using var audit = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 8 });
            policyAudit |= audit.RootElement.GetProperty("backend").GetString() == "processcontainer"
                && audit.RootElement.GetProperty("config_schema_version").GetString() == "1.0.0";
        }
        Check(policyAudit, "official_private_policy_audit_missing");

        // PTY bytes remain untrusted output. This envelope is only a required
        // agreement with the inaccessible-to-payload native failure log and
        // OS Job history above, never an independent source of launch state.
        var replay = session.ReadReplay(0, 32_768);
        Check(replay.GapFrom is null && replay.NextSequence == replay.AvailableUntil && replay.DrainFailure is null, "official_refusal_envelope_capture_incomplete");
        var text = WindowsTerminalCapture.FixtureParsingView(new UTF8Encoding(false, true).GetString(replay.Data));
        const string prefix = "{\"error\":";
        var offset = text.IndexOf(prefix, StringComparison.Ordinal);
        Check(offset >= 0 && text.IndexOf(prefix, offset + prefix.Length, StringComparison.Ordinal) < 0, "official_refusal_envelope_missing_or_ambiguous");
        using var envelope = JsonDocument.Parse(text.AsMemory(offset), new JsonDocumentOptions { MaxDepth = 8 });
        var error = envelope.RootElement.GetProperty("error");
        Check(error.GetProperty("code").GetString() == "backend_error" && error.GetProperty("message").GetString() == message
            && error.GetProperty("extended_error").GetString() == extended, "official_refusal_envelope_disagrees_with_private_log");
        result.PrivateDiagnostics.Add(new("executor-diagnostic.log", Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes.Length));
    }

    private static string RemoveOfficialLogTimestamps(string text)
    {
        var output = new StringBuilder(text.Length);
        for (var index = 0; index < text.Length; index++)
        {
            if (text[index] == '[')
            {
                var end = index + 1;
                while (end < text.Length && char.IsAsciiDigit(text[end])) end++;
                if (end > index + 1 && end + 1 < text.Length && text[end] == ']' && text[end + 1] == ' ')
                {
                    index = end + 1;
                    continue;
                }
            }
            output.Append(text[index]);
        }
        return output.ToString();
    }

    private static async Task<WindowsQualificationCase> MissingPolicyAsync(string stage, string work)
    {
        var root = NewRoot(work, "reject-missing-policy");
        var owned = CreateOwned(root);
        var control = Path.Combine(root, "private control");
        WindowsPolicy.CreatePrivateControl(control);
        var missing = Path.Combine(control, "request.json");
        var entry = Path.Combine(owned.Work, "payload-entry.txt");
        var policy = new WindowsPolicyArtifact(control, missing, "", 0);
        var acls = Owned(owned).Concat([control]).ToDictionary(path => path, AclHash, StringComparer.OrdinalIgnoreCase);
        var fixture = new Fixture(owned, policy, acls, "");
        var result = new WindowsQualificationCase { Name = "reject-missing-policy", Protocol = "MXC-WIN-01", ExitSource = "official_executor_config_rejection" };
        var wrapperRejected = false;
        Process? process = null;
        byte[] output = [];
        byte[] errors = [];
        var watch = Stopwatch.StartNew();
        try
        {
            var executor = Path.Combine(stage, "wxc-exec.exe");
            using var lease = File.Open(executor, FileMode.Open, FileAccess.Read, FileShare.Read);
            Check(Convert.ToHexStringLower(SHA256.HashData(lease)) == Program.WindowsNative["wxc-exec.exe"], "missing_policy_executor_identity_mismatch");
            Check(!File.Exists(missing) && !File.Exists(entry), "missing_policy_fixture_not_fresh");
            ConPtySession? unexpected = null;
            try { unexpected = ConPtySession.Start(new(executor, missing, control, 80, 24, new(5000, 1024UL * 1024 * 1024, 16))); }
            catch (FileNotFoundException exception) when (exception.FileName is null || Path.GetFullPath(exception.FileName).Equals(missing, StringComparison.OrdinalIgnoreCase))
            {
                // ValidatePath reads this nonexistent file before any Job,
                // pseudoconsole or CreateProcess call in ConPtySession.Start.
                wrapperRejected = true;
            }
            if (unexpected is not null)
            {
                result.UnresolvedCleanupOwner = unexpected;
                try { await unexpected.DisposeAsync().ConfigureAwait(false); result.UnresolvedCleanupOwner = null; }
                catch (Exception exception)
                {
                    result.CleanupFailure = WindowsQualification.ObserveFailure(exception);
                    throw;
                }
            }
            Check(wrapperRejected, "missing_policy_wrapper_did_not_refuse");

            // Independently exercise the real official config-reader rejection.
            // This trusted parser invocation is not a ConPTY/Job qualification,
            // and its fields do not claim an observed empty Job.
            var start = new ProcessStartInfo(executor)
            {
                UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = control,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            start.ArgumentList.Add("--config");
            start.ArgumentList.Add(missing);
            start.Environment.Clear();
            start.Environment["SystemRoot"] = Path.GetDirectoryName(Environment.SystemDirectory)!;
            start.Environment["PATH"] = "";
            start.Environment["LOCALAPPDATA"] = owned.Cache;
            start.Environment["TEMP"] = owned.Temp;
            start.Environment["TMP"] = owned.Temp;
            process = Process.Start(start) ?? throw new IOException("Official config reader did not start.");
            _ = process.SafeHandle;
            result.ExecutorProcessId = checked((uint)process.Id);
            result.ExecutorStartUtc = process.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var stdout = ReadRefusalAsync(process.StandardOutput.BaseStream, deadline.Token);
            var stderr = ReadRefusalAsync(process.StandardError.BaseStream, deadline.Token);
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(deadline.Token)).ConfigureAwait(false);
            output = await stdout.ConfigureAwait(false);
            errors = await stderr.ConfigureAwait(false);
            var exit = unchecked((uint)process.ExitCode);
            result.RawExecutorExit = exit;
            Check(exit != 0 && (exit & 0x80000000) == 0, "missing_policy_official_reader_did_not_refuse");
            Check(output.Length + errors.Length > 0 && !File.Exists(missing) && !File.Exists(entry), "missing_policy_native_refusal_evidence_missing");
            result.Passed = true;
        }
        catch (ConPtyLaunchException exception)
        {
            if (exception.InnerException is AggregateException combined && combined.InnerExceptions.Count >= 2)
            {
                Fail(result, combined.InnerExceptions[0]);
                result.CleanupFailure = WindowsQualification.ObserveFailure(combined.InnerExceptions[1]);
            }
            else { Fail(result, exception); }
            result.UnresolvedCleanupOwner = exception.CleanupOwner;
        }
        catch (Exception exception) { Fail(result, exception); }
        finally
        {
            if (process is not null)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill();
                        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                        await process.WaitForExitAsync(cleanup.Token).ConfigureAwait(false);
                    }
                    result.CleanupCompleted = process.HasExited;
                    process.Dispose();
                }
                catch (Exception exception)
                {
                    result.CleanupFailure = WindowsQualification.ObserveFailure(exception);
                    result.Passed = false;
                    UnresolvedMissingPolicyProcess = process;
                }
            }
            result.ElapsedMs = watch.Elapsed.TotalMilliseconds;
        }
        Evidence(result, control, "missing-policy-observations.json", writer =>
        {
            writer.WriteBoolean("wrapperPrelaunchRejected", wrapperRejected);
            writer.WriteBoolean("officialConfigReaderExecuted", process is not null);
            writer.WriteBoolean("officialConfigFileAbsent", !File.Exists(missing));
            writer.WriteBoolean("entryFileAbsent", !File.Exists(entry));
            writer.WriteBoolean("jobObservationApplicable", false);
            writer.WriteString("stdoutSha256", Convert.ToHexStringLower(SHA256.HashData(output)));
            writer.WriteString("stderrSha256", Convert.ToHexStringLower(SHA256.HashData(errors)));
            writer.WriteString("scope", "Wrapper prelaunch refusal and a separate bounded official --config rejection; neither is a --probe-only pass or a payload start-identity claim.");
        });
        CheckAcls(result, fixture);
        return result;
    }

    private static async Task<byte[]> ReadRefusalAsync(Stream input, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        int count;
        while ((count = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
        {
            Check(output.Length + count <= 65_536, "missing_policy_diagnostic_bound");
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }

    private sealed record PolicyFileContract(bool ExistingControlRejected, bool CreateNewRejected, bool ReplacementRejected, bool DeletionRejected);

    private static PolicyFileContract VerifyPolicyFileContract(WindowsPolicyArtifact policy)
    {
        Check(HashFile(policy.Path) == policy.Sha256, "private_policy_initial_hash_mismatch");
        var request = JsonSerializer.Deserialize(File.ReadAllBytes(policy.Path), WindowsPolicyJson.Default.WindowsPolicyRequest)
            ?? throw new InvalidDataException("Private admission policy is missing.");
        var existingControlRejected = false;
        try { _ = WindowsPolicy.WritePrivate(policy.ControlDirectory, request); }
        catch (Win32Exception exception) when (exception.NativeErrorCode is 80 or 183) { existingControlRejected = true; }
        Check(existingControlRejected && HashFile(policy.Path) == policy.Sha256, "private_control_collision_not_refused");
        var createNewRejected = false;
        try { using var collision = new FileStream(policy.Path, FileMode.CreateNew, FileAccess.Write, FileShare.Read); }
        catch (IOException exception) when ((exception.HResult & 0xffff) is 80 or 183) { createNewRejected = true; }
        Check(createNewRejected && HashFile(policy.Path) == policy.Sha256, "private_policy_create_new_not_refused");
        var replacement = Path.Combine(policy.ControlDirectory, "replacement-attempt.json");
        using (var candidate = new FileStream(replacement, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        {
            candidate.Write("owned replacement attempt"u8);
            candidate.Flush(flushToDisk: true);
        }
        var replacementRejected = false;
        var deletionRejected = false;
        using (var readLease = File.Open(policy.Path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            try { File.Move(replacement, policy.Path, overwrite: true); }
            catch (IOException exception) when ((exception.HResult & 0xffff) is 32 or 33) { replacementRejected = true; }
            catch (UnauthorizedAccessException exception) when ((exception.HResult & 0xffff) == 5) { replacementRejected = true; }
            try { File.Delete(policy.Path); }
            catch (IOException exception) when ((exception.HResult & 0xffff) is 32 or 33) { deletionRejected = true; }
            catch (UnauthorizedAccessException exception) when ((exception.HResult & 0xffff) == 5) { deletionRejected = true; }
            Check(replacementRejected && deletionRejected && HashFile(policy.Path) == policy.Sha256, "private_policy_read_lease_did_not_protect");
        }
        Check(HashFile(policy.Path) == policy.Sha256, "private_policy_hash_changed_after_owner_lease");
        return new(existingControlRejected, createNewRejected, replacementRejected, deletionRejected);
    }

    private static Fixture CreateFixture(string stage, string work, string name, string[] workload, Action<WindowsPolicyRequest>? change = null)
    {
        var root = NewRoot(work, name);
        var owned = CreateOwned(root);
        var control = Path.Combine(root, "private control");
        var request = WindowsPolicy.BuildRequest(Path.Combine(stage, "arcforges-mxc-probe.exe"), ["--windows-workload", .. workload], owned,
            [stage, Environment.SystemDirectory], [control], WindowsNetworkChoice.DenyAll);
        change?.Invoke(request);
        var events = WindowsQualification.EnableFixtureEvents(request, owned.Work);
        var policy = WindowsPolicy.WritePrivate(control, request);
        return new Fixture(owned, policy, FixtureSnapshots(owned, policy, []), events);
    }

    private static string NewRoot(string work, string name)
    {
        var root = Path.GetFullPath(Path.Combine(work, name));
        if (Directory.Exists(root) || File.Exists(root)) throw new InvalidDataException("Policy-case fixture already exists.");
        Directory.CreateDirectory(root);
        return root;
    }

    private static WindowsOwnedPaths CreateOwned(string root)
    {
        var parent = Path.Combine(root, "owned 工作区");
        var owned = new WindowsOwnedPaths(Path.Combine(parent, "home"), Path.Combine(parent, "config"), Path.Combine(parent, "cache"),
            Path.Combine(parent, "temp"), Path.Combine(parent, "work"), Path.Combine(parent, "data"));
        foreach (var path in Owned(owned)) Directory.CreateDirectory(path);
        return owned;
    }

    private static string[] Owned(WindowsOwnedPaths owned) => [owned.Home, owned.Config, owned.Cache, owned.Temp, owned.Work, owned.Data];

    private static string Seed(string directory)
    {
        var path = Path.Combine(directory, "seed.txt");
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        output.Write(FileSentinel);
        output.Flush(flushToDisk: true);
        return path;
    }

    private static WindowsPolicyArtifact MalformedPolicy(string control)
    {
        WindowsPolicy.CreatePrivateControl(control);
        var path = Path.Combine(control, "request.json");
        var bytes = "{\"version\":"u8.ToArray();
        using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
        {
            output.Write(bytes);
            output.Flush(flushToDisk: true);
        }
        WindowsPolicy.VerifyPrivateFile(path);
        return new(control, path, HashFile(path), bytes.Length);
    }

    private sealed record Fixture(WindowsOwnedPaths Owned, WindowsPolicyArtifact Policy, Dictionary<string, string> Acls, string EventsDirectory);

    private static Dictionary<string, string> FixtureSnapshots(WindowsOwnedPaths owned, WindowsPolicyArtifact policy, IEnumerable<string> additional)
    {
        var paths = Owned(owned).Concat([policy.ControlDirectory, policy.Path]).Concat(additional).Distinct(StringComparer.OrdinalIgnoreCase);
        return paths.ToDictionary(path => path, AclHash, StringComparer.OrdinalIgnoreCase);
    }

    private static void CheckAcls(WindowsQualificationCase result, Fixture fixture)
    {
        try
        {
            var after = fixture.Acls.Keys.ToDictionary(path => path, AclHash, StringComparer.OrdinalIgnoreCase);
            var matches = fixture.Acls.All(item => after[item.Key] == item.Value);
            Evidence(result, fixture.Policy.ControlDirectory, "owned-acl-observations.json", writer =>
            {
                writer.WriteNumber("ownedFixtureObjects", fixture.Acls.Count);
                writer.WriteBoolean("unchanged", matches);
                writer.WriteStartArray("snapshots");
                var index = 0;
                foreach (var item in fixture.Acls)
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("ownedFixtureIndex", index++);
                    writer.WriteString("beforeSha256", item.Value);
                    writer.WriteString("afterSha256", after[item.Key]);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
            });
            Check(matches, "owned_host_acl_changed");
        }
        catch (Exception exception) { Fail(result, exception); }
    }

    private static void Evidence(WindowsQualificationCase result, string control, string name, Action<Utf8JsonWriter> fields)
    {
        try
        {
            using var memory = new MemoryStream();
            using (var writer = new Utf8JsonWriter(memory))
            {
                writer.WriteStartObject(); fields(writer); writer.WriteEndObject();
            }
            var bytes = memory.ToArray();
            Check(bytes.Length <= WindowsPolicy.MaximumUtf8Bytes, "policy_case_evidence_bound");
            var path = Path.Combine(control, name);
            using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            {
                output.Write(bytes); output.Flush(flushToDisk: true);
            }
            WindowsPolicy.VerifyPrivateFile(path);
            result.PrivateDiagnostics.Add(new(name, Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes.Length));
        }
        catch (Exception exception) { result.EvidenceFailure = WindowsQualification.ObserveFailure(exception); result.Passed = false; }
    }

    private static void CheckDigest(JsonElement item, string expected, string code)
    {
        var bytes = Encoding.UTF8.GetBytes(expected);
        Check(item.GetProperty("length").GetInt32() == expected.Length && item.GetProperty("utf8Bytes").GetInt32() == bytes.Length
            && item.GetProperty("sha256").GetString() == Convert.ToHexStringLower(SHA256.HashData(bytes)), code);
    }

    private static string HashFile(string path)
    {
        using var input = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(input));
    }

    private static void Check(bool condition, string code) => WindowsQualification.Check(condition, code);

    private static void Fail(WindowsQualificationCase result, Exception exception)
    {
        result.Passed = false;
        result.PrimaryFailure ??= WindowsQualification.ObserveFailure(exception);
        result.FailureCode ??= WindowsQualification.FailureCode(exception);
        result.FailureType ??= exception.GetType().Name;
        if (result.FailureHResult == 0) result.FailureHResult = exception.HResult;
    }

    internal static string AclHash(string path)
    {
        const uint ownerGroupDacl = 0x1 | 0x2 | 0x4;
        var error = GetNamedSecurityInfo(path, 1, ownerGroupDacl, out _, out _, out _, out _, out var descriptor);
        if (error != 0) throw new Win32Exception((int)error, "Read owned fixture ACL");
        try
        {
            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, 1, ownerGroupDacl, out var text, out _))
                throw NativeError("Read owned fixture security descriptor");
            try { return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Marshal.PtrToStringUni(text) ?? throw new InvalidDataException("Empty owned fixture descriptor.")))); }
            finally { _ = LocalFree(text); }
        }
        finally { _ = LocalFree(descriptor); }
    }

    private static unsafe void CreateJunction(string path, string target)
    {
        Directory.CreateDirectory(path);
        using var handle = CreateFile(path, 0x40000000, 0x1 | 0x2 | 0x4, 0, 3, 0x02000000 | 0x00200000, 0);
        if (handle.IsInvalid) throw NativeError("Open owned junction fixture");
        var substitute = Encoding.Unicode.GetBytes("\\??\\" + Path.GetFullPath(target));
        var print = Encoding.Unicode.GetBytes(Path.GetFullPath(target));
        var buffer = new byte[16 + substitute.Length + 2 + print.Length + 2];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, 0xa0000003);
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(4), checked((ushort)(buffer.Length - 8)));
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(10), checked((ushort)substitute.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(12), checked((ushort)(substitute.Length + 2)));
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(14), checked((ushort)print.Length));
        substitute.CopyTo(buffer, 16);
        print.CopyTo(buffer, 18 + substitute.Length);
        fixed (byte* data = buffer)
            if (!DeviceIoControl(handle, 0x000900a4, data, (uint)buffer.Length, 0, 0, out _, 0)) throw NativeError("Create owned junction fixture");
        Check((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0, "real_reparse_fixture_missing");
    }

    private static Win32Exception NativeError(string operation) => new(Marshal.GetLastPInvokeError(), operation);
    [LibraryImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint GetNamedSecurityInfo(string path, int objectType, uint information, out nint owner, out nint group, out nint dacl, out nint sacl, out nint descriptor);
    [LibraryImport("advapi32.dll", EntryPoint = "ConvertSecurityDescriptorToStringSecurityDescriptorW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static partial bool ConvertSecurityDescriptorToStringSecurityDescriptor(nint descriptor, uint revision, uint information, out nint text, out uint length);
    [LibraryImport("kernel32.dll")] private static partial nint LocalFree(nint memory);
    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFile(string path, uint access, uint share, nint attributes, uint disposition, uint flags, nint template);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static unsafe partial bool DeviceIoControl(SafeFileHandle file, uint code, void* input, uint inputBytes, nint output, uint outputBytes, out uint returned, nint overlapped);
}
