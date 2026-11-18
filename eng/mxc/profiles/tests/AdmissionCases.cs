// SPDX-License-Identifier: AGPL-3.0-only

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Node.Platform.Capabilities;

string profileDirectory = args[0];
string stage = args[1];
string scratch = args[2];
bool windows = OperatingSystem.IsWindows();
if (!windows && !OperatingSystem.IsLinux())
{
    throw new PlatformNotSupportedException("Admission cases require native Windows or Linux.");
}

const MxcPrerequisites common = MxcPrerequisites.ProtectedInstallation | MxcPrerequisites.PrivateControlPaths;
const MxcPrerequisites windowsInputs =
    MxcPrerequisites.WindowsNativeDenyPaths | MxcPrerequisites.WindowsConPty | MxcPrerequisites.WindowsNestedJob;
const MxcPrerequisites linuxInputs =
    MxcPrerequisites.LinuxBubblewrap | MxcPrerequisites.LinuxNamespaces | MxcPrerequisites.LinuxPty
    | MxcPrerequisites.LinuxUserManager | MxcPrerequisites.LinuxCgroupV2 | MxcPrerequisites.LinuxCpuController
    | MxcPrerequisites.LinuxMemoryController | MxcPrerequisites.LinuxPidsController
    | MxcPrerequisites.LinuxSelectedNetworkHelpers;

string profile = windows ? MxcProfileAdmission.WindowsProfileId : MxcProfileAdmission.LinuxProfileId;
string revision = windows ? MxcProfileAdmission.WindowsProfileRevision : MxcProfileAdmission.LinuxProfileRevision;
string receiptPath = Path.Combine(profileDirectory, profile + ".qualification.json");
byte[] receipt = File.ReadAllBytes(receiptPath);
using var receiptDocument = JsonDocument.Parse(receipt);
using var manifestDocument = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(stage, "mxc-manifest.json")));
JsonElement manifest = manifestDocument.RootElement;
JsonElement official = receiptDocument.RootElement.GetProperty("official");
var manifestHashes = manifest.GetProperty("files").EnumerateArray().ToDictionary(
    item => Text(item, "path"), item => Text(item, "sha256"), StringComparer.Ordinal);
var nativeHashes = official.GetProperty("runtimeFiles").EnumerateArray().ToDictionary(
    item => Text(item, "path"),
    item =>
    {
        string name = Text(item, "path");
        string observed = FileHash(Path.Combine(stage, name));
        if (!StringComparer.Ordinal.Equals(manifestHashes[name], observed))
        {
            throw new InvalidDataException($"Native stage member '{name}' did not match its original manifest.");
        }

        return observed;
    },
    StringComparer.Ordinal);

var request = new MxcProfileRequest(profile, revision, MxcTerminalMode.Interactive,
    MxcFilePolicy.OwnedRootWithExplicitGrants, MxcNetworkMode.DefaultDeny,
    MxcEnvironmentPolicy.CleanExplicit, MxcResourcePolicy.CpuMemoryAndProcessCount,
    MxcRecoveryPolicy.AuthenticatedOwner);

// Complete flags drive the decision regression cases. Only the absent path below is
// measured as a live prerequisite here. Native composition comes from the original receipts.
var host = new MxcHostFacts(
    RuntimeInformation.RuntimeIdentifier,
    windows ? Environment.OSVersion.Version.ToString() : LinuxOsIdentity(),
    windows ? null : File.ReadAllText("/proc/sys/kernel/osrelease").Trim(),
    windows ? null : File.ReadAllText("/proc/sys/kernel/version").Trim(),
    Text(manifest, "version"), Text(manifest, "schema"), Text(manifest, "source"),
    Text(manifest, "packageSha256"), Text(manifest, "releaseSha256"),
    windows ? "process-container/base-container" : "bubblewrap",
    nativeHashes, common | (windows ? windowsInputs : linuxInputs),
    windows ? null : SystemdVersion(),
    windows ? null : ReadLinuxHelpers());

Expect("matching receipt and platform", request, host, receipt, MxcAdmissionDecision.Admitted, MxcEvidenceStatus.Verified);
string absentReceipt = Path.Combine(scratch, "absent.qualification.json");
byte[] missingEvidence = File.Exists(absentReceipt) ? File.ReadAllBytes(absentReceipt) : [];
Expect("missing receipt", request, host, missingEvidence, MxcAdmissionDecision.EvidenceMissing);
Expect("receipt bytes altered", request, host, [.. receipt, (byte)'\n'], MxcAdmissionDecision.EvidenceMismatch);
Expect("stale OS", request, host with { OperatingSystem = "stale-os" }, receipt, MxcAdmissionDecision.EvidenceMismatch);
Expect("changed SDK", request, host with { SdkVersion = "0.0.0" }, receipt, MxcAdmissionDecision.EvidenceMismatch);
Expect("missing official member", request, host with { NativeMemberSha256 = new Dictionary<string, string>() },
    receipt, MxcAdmissionDecision.EvidenceMismatch);
Expect("unadmitted host network", request with { Network = MxcNetworkMode.SharedHostNetwork }, host,
    receipt, MxcAdmissionDecision.UnsupportedCombination);
Expect("weaker resource policy", request with { Resources = MxcResourcePolicy.ObserveOnly }, host,
    receipt, MxcAdmissionDecision.UnsupportedCombination);

string privateRoot = Path.Combine(scratch, "isolated-prerequisites");
Directory.CreateDirectory(privateRoot);
MxcPrerequisites missing = windows ? MxcPrerequisites.PrivateControlPaths : MxcPrerequisites.LinuxBubblewrap;
bool exists = windows
    ? Directory.Exists(Path.Combine(privateRoot, "private-control"))
    : File.Exists(Path.Combine(privateRoot, "bwrap"));
if (exists)
{
    throw new InvalidOperationException("The negative fixture unexpectedly contains the prerequisite path.");
}

var refusal = Expect(windows ? "absent private control path" : "absent Bubblewrap executable", request,
    host with { Prerequisites = host.Prerequisites & ~missing }, receipt, MxcAdmissionDecision.PrerequisiteMissing);
if ((refusal.MissingPrerequisites & missing) == 0)
{
    throw new InvalidOperationException($"Native refusal did not name {missing}.");
}

if (windows)
{
    var external = request with { Network = MxcNetworkMode.WindowsExternalSelectedTcpUdp };
    Expect("external selected-network request", external, host, receipt,
        MxcAdmissionDecision.Admitted, MxcEvidenceStatus.Unverified);
    Expect("verified external selected-network request", external with { RequireVerifiedNetwork = true }, host, receipt,
        MxcAdmissionDecision.Unverified, MxcEvidenceStatus.Unverified);
    var pipes = request with { Terminal = MxcTerminalMode.Pipes };
    var result = Expect("explicit pipe request", pipes, host, receipt, MxcAdmissionDecision.Admitted);
    if (result.TerminalEvidence != MxcEvidenceStatus.Unverified)
    {
        throw new InvalidOperationException("Explicit Windows pipes lack full-composition evidence.");
    }

    Expect("verified pipe request", pipes with { RequireVerifiedTerminal = true }, host, receipt,
        MxcAdmissionDecision.Unverified);
}
else
{
    var selected = request with { Network = MxcNetworkMode.LinuxSelectedIpv4 };
    Expect("literal IPv4 selection", selected, host, receipt, MxcAdmissionDecision.Admitted, MxcEvidenceStatus.Verified);
    var changedHelpers = new Dictionary<string, string>(host.LinuxHelperSha256!, StringComparer.Ordinal)
    {
        ["bwrap"] = new string('0', 64),
    };
    Expect("changed Bubblewrap binary", request, host with { LinuxHelperSha256 = changedHelpers }, receipt,
        MxcAdmissionDecision.EvidenceMismatch);
    Expect("selected IPv4 needs all helpers", selected,
        host with { Prerequisites = host.Prerequisites & ~MxcPrerequisites.LinuxSelectedNetworkHelpers }, receipt,
        MxcAdmissionDecision.PrerequisiteMissing);
}

static MxcAdmissionResult Expect(string name, MxcProfileRequest request, MxcHostFacts host, byte[] receipt,
    MxcAdmissionDecision decision, MxcEvidenceStatus? networkEvidence = null)
{
    MxcAdmissionResult result = MxcProfileAdmission.Evaluate(request, host, receipt);
    if (result.Decision != decision || result.Admitted != (decision == MxcAdmissionDecision.Admitted)
        || (networkEvidence.HasValue && result.NetworkEvidence != networkEvidence))
    {
        throw new InvalidOperationException($"{name}: expected {decision}/{networkEvidence}, got {result}.");
    }

    Console.WriteLine($"PASS {name}: {result.Decision}; feature={result.Feature ?? "-"}; "
        + $"reason={result.Reason ?? "-"}; missing={result.MissingPrerequisites}; evidence={result.EvidenceId ?? "-"}");
    return result;
}

static string Text(JsonElement value, string property) => value.GetProperty(property).GetString()
    ?? throw new InvalidDataException($"Missing '{property}' value.");

static string FileHash(string path)
{
    using FileStream input = File.OpenRead(path);
    return Convert.ToHexStringLower(SHA256.HashData(input));
}

static string LinuxOsIdentity()
{
    var values = File.ReadLines("/etc/os-release")
        .Select(line => line.Split('=', 2)).Where(parts => parts.Length == 2)
        .ToDictionary(parts => parts[0], parts => parts[1].Trim('"'), StringComparer.Ordinal);
    return $"{values["ID"]}/{values["VERSION_ID"]}";
}

static string SystemdVersion()
{
    using Process command = Process.Start(new ProcessStartInfo("/usr/bin/systemctl", "--user show --property=Version --value")
    {
        UseShellExecute = false,
        RedirectStandardOutput = true,
    }) ?? throw new InvalidOperationException("Could not inspect the installed systemd version.");
    string output = command.StandardOutput.ReadToEnd();
    command.WaitForExit();
    return command.ExitCode == 0 && !string.IsNullOrWhiteSpace(output)
        ? output.Trim()
        : throw new InvalidOperationException("Could not read the systemd user manager version.");
}

static Dictionary<string, string> ReadLinuxHelpers()
{
    string[] search = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
    string[] names = ["bwrap", "sh", "slirp4netns", "ip", "unshare", "nsenter",
        "iptables", "ip6tables", "iptables-restore", "ip6tables-restore"];
    var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
    foreach (string name in names)
    {
        string? path = search.Select(directory => Path.Combine(directory, name)).FirstOrDefault(File.Exists);
        if (path is not null)
        {
            hashes.Add(name, FileHash(path));
        }
    }

    return hashes;
}
