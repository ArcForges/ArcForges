// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.CommandLine;

/// <summary>
/// The canonical protobuf JSON of <see cref="NodeInfo"/> (contracts README section 8), written without the protobuf reflection
/// descriptors. Building the <c>arcforges.node.v1</c> descriptors costs about 35 ms in a cold Native AOT process, which alone would
/// exceed the status round-trip target (15 section 1: <c>arcforges status --json</c> p50 at most 60 ms); this writer emits exactly
/// what <c>JsonFormatter</c> emits for the message (a test compares the two), with <c>*Id</c> fields as base32 text like every other
/// CLI document.
/// </summary>
public static class NodeInfoJson
{
    /// <summary>Writes <paramref name="info"/> as one JSON object.</summary>
    public static void Write(Utf8JsonWriter writer, NodeInfo info)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(info);
        writer.WriteStartObject();
        if (info.Node is { } node)
        {
            writer.WriteStartObject("node");
            WriteId(writer, "nodeId", node.NodeId);
            if (node.HasName)
            {
                writer.WriteString("name", node.Name);
            }

            if (node.HasRole)
            {
                WriteEnum(writer, "role", "NODE_ROLE", node.Role.ToString(), (int)node.Role);
            }

            if (node.HasOs)
            {
                WriteEnum(writer, "os", "OS_FAMILY", node.Os.ToString(), (int)node.Os);
            }

            if (node.HasArch)
            {
                WriteEnum(writer, "arch", "CPU_ARCHITECTURE", node.Arch.ToString(), (int)node.Arch);
            }

            writer.WriteEndObject();
        }

        if (info.HasVersion)
        {
            writer.WriteString("version", info.Version);
        }

        if (info.HasContractMajor)
        {
            writer.WriteNumber("contractMajor", info.ContractMajor);
        }

        if (info.HasContractMinor)
        {
            writer.WriteNumber("contractMinor", info.ContractMinor);
        }

        if (info.Features.Count > 0)
        {
            writer.WriteStartArray("features");
            foreach (var feature in info.Features)
            {
                writer.WriteStringValue(feature);
            }

            writer.WriteEndArray();
        }

        if (info.HasDataRoot)
        {
            writer.WriteString("dataRoot", info.DataRoot);
        }

        if (info.HasEndpoint)
        {
            writer.WriteString("endpoint", info.Endpoint);
        }

        WriteInstant(writer, "startedAt", info.StartedAt);
        if (info.HasStoreBytes)
        {
            writer.WriteString("storeBytes", info.StoreBytes.ToString(CultureInfo.InvariantCulture));
        }

        if (info.Capabilities is { } capabilities)
        {
            WriteCapabilities(writer, capabilities);
        }

        if (info.HasUpdateChannel)
        {
            writer.WriteString("updateChannel", info.UpdateChannel);
        }

        if (info.HasAccountLinked)
        {
            writer.WriteBoolean("accountLinked", info.AccountLinked);
        }

        if (info.HasLanEnabled)
        {
            writer.WriteBoolean("lanEnabled", info.LanEnabled);
        }

        if (info.HasEdition)
        {
            WriteEnum(writer, "edition", "EDITION", info.Edition.ToString(), (int)info.Edition);
        }

        if (info.HasState)
        {
            WriteEnum(writer, "state", "NODE_LIFECYCLE_STATE", info.State.ToString(), (int)info.State);
        }

        writer.WriteEndObject();
    }

    /// <summary>The proto enum value name of a C# enum member (<c>ObserveOnly</c> in <c>CPU_CONTROL</c> is <c>CPU_CONTROL_OBSERVE_ONLY</c>).</summary>
    public static string EnumName(string prefix, string member)
    {
        ArgumentNullException.ThrowIfNull(member);
        var builder = new StringBuilder(prefix.Length + member.Length + 8).Append(prefix);
        for (var i = 0; i < member.Length; i++)
        {
            var character = member[i];
            var boundary = i == 0
                || (char.IsUpper(character) && (char.IsLower(member[i - 1]) || char.IsDigit(member[i - 1])
                    || (i + 1 < member.Length && char.IsLower(member[i + 1]) && char.IsUpper(member[i - 1]))));
            if (boundary)
            {
                builder.Append('_');
            }

            builder.Append(char.ToUpperInvariant(character));
        }

        return builder.ToString();
    }

    private static void WriteCapabilities(Utf8JsonWriter writer, CapabilityReport report)
    {
        writer.WriteStartObject("capabilities");
        if (report.HasCpu)
        {
            WriteEnum(writer, "cpu", "CPU_CONTROL", report.Cpu.ToString(), (int)report.Cpu);
        }

        Text(writer, "cpuReason", report.HasCpuReason, report.CpuReason);
        if (report.HasMemory)
        {
            WriteEnum(writer, "memory", "MEMORY_CONTROL", report.Memory.ToString(), (int)report.Memory);
        }

        Text(writer, "memoryReason", report.HasMemoryReason, report.MemoryReason);
        if (report.HasPids)
        {
            WriteEnum(writer, "pids", "PROCESS_COUNT_CONTROL", report.Pids.ToString(), (int)report.Pids);
        }

        Text(writer, "pidsReason", report.HasPidsReason, report.PidsReason);
        if (report.HasIo)
        {
            WriteEnum(writer, "io", "IO_CONTROL", report.Io.ToString(), (int)report.Io);
        }

        Text(writer, "ioReason", report.HasIoReason, report.IoReason);
        if (report.HasPause)
        {
            WriteEnum(writer, "pause", "PAUSE_SUPPORT", report.Pause.ToString(), (int)report.Pause);
        }

        Text(writer, "pauseReason", report.HasPauseReason, report.PauseReason);
        if (report.HasKillTree)
        {
            WriteEnum(writer, "killTree", "KILL_TREE_GUARANTEE", report.KillTree.ToString(), (int)report.KillTree);
        }

        Text(writer, "killTreeReason", report.HasKillTreeReason, report.KillTreeReason);
        if (report.HasAdopt)
        {
            WriteEnum(writer, "adopt", "ADOPT_SUPPORT", report.Adopt.ToString(), (int)report.Adopt);
        }

        Text(writer, "adoptReason", report.HasAdoptReason, report.AdoptReason);
        if (report.HasRestartSurvival)
        {
            writer.WriteBoolean("restartSurvival", report.RestartSurvival);
        }

        Text(writer, "restartSurvivalReason", report.HasRestartSurvivalReason, report.RestartSurvivalReason);
        WriteInstant(writer, "evaluatedAt", report.EvaluatedAt);
        if (report.PlatformFacts.Count > 0)
        {
            writer.WriteStartArray("platformFacts");
            foreach (var fact in report.PlatformFacts)
            {
                writer.WriteStartObject();
                Text(writer, "name", fact.HasName, fact.Name);
                Text(writer, "value", fact.HasValue, fact.Value);
                if (fact.HasRedacted)
                {
                    writer.WriteBoolean("redacted", fact.Redacted);
                }

                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        }

        writer.WriteEndObject();
    }

    private static void Text(Utf8JsonWriter writer, string name, bool present, string value)
    {
        if (present)
        {
            writer.WriteString(name, value);
        }
    }

    private static void WriteEnum(Utf8JsonWriter writer, string name, string prefix, string member, int value)
    {
        // An unknown value (a newer node) prints as its number, as JsonFormatter does.
        if (int.TryParse(member, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _))
        {
            writer.WriteNumber(name, value);
            return;
        }

        writer.WriteString(name, EnumName(prefix, member));
    }

    private static void WriteId(Utf8JsonWriter writer, string name, Id? id)
    {
        if (id is null)
        {
            return;
        }

        if (id.Value.Length == 16)
        {
            writer.WriteString(name, IdText.Format(id.Value.Span));
        }
        else
        {
            writer.WriteStartObject(name);
            if (id.HasValue)
            {
                writer.WriteString("value", Convert.ToBase64String(id.Value.Span));
            }

            writer.WriteEndObject();
        }
    }

    private static void WriteInstant(Utf8JsonWriter writer, string name, Instant? instant)
    {
        if (instant is null)
        {
            return;
        }

        writer.WriteStartObject(name);
        if (instant.HasUnixSeconds)
        {
            writer.WriteString("unixSeconds", instant.UnixSeconds.ToString(CultureInfo.InvariantCulture));
        }

        if (instant.HasNanos)
        {
            writer.WriteNumber("nanos", instant.Nanos);
        }

        writer.WriteEndObject();
    }
}
