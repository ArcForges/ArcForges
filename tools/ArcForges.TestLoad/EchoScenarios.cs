// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;

namespace ArcForges.TestLoad;

/// <summary>
/// Deterministic I/O probes for capture tests (R-EXE-003, R-EXE-004): <c>args</c> prints its own argument vector and working directory as
/// one JSON object (what a program received, to compare a managed run with a direct one), and <c>echo</c> copies standard input to
/// standard output byte for byte until end-of-file (the stdin modes).
/// </summary>
internal static class EchoScenarios
{
    /// <summary><c>arcforges-testload args [anything...]</c>: <c>{"argv": [...], "cwd": "..."}</c> on standard output, UTF-8.</summary>
    public static int PrintArguments(IReadOnlyList<string> arguments)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteStartArray("argv");
            foreach (var argument in arguments)
            {
                writer.WriteStringValue(argument);
            }

            writer.WriteEndArray();
            writer.WriteString("cwd", Environment.CurrentDirectory);
            writer.WriteEndObject();
        }

        using var output = Console.OpenStandardOutput();
        output.Write(buffer.ToArray());
        output.Write("\n"u8);
        return ExitCodes.Success;
    }

    /// <summary><c>arcforges-testload echo</c>: standard input to standard output, byte for byte.</summary>
    public static int CopyInput()
    {
        using var input = Console.OpenStandardInput();
        using var output = Console.OpenStandardOutput();
        var buffer = new byte[64 * 1024];
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            output.Write(buffer, 0, read);
            output.Flush();
        }

        return ExitCodes.Success;
    }
}
