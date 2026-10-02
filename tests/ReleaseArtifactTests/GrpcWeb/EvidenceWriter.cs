// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using ArcForges.Contracts.Hello.V1;

namespace ArcForges.ReleaseArtifactTests.GrpcWeb;

/// <summary>
/// Writes the run record with Utf8JsonWriter (no reflection, so it is Native AOT safe). It contains the target
/// origin and path, the check outcomes and the runtime identity. It never contains a header value other than the
/// worker revision, a request or response body, or any credential.
/// </summary>
internal static class EvidenceWriter
{
    public const string Schema = "arcforges.prf-05.evidence.v1";

    public static string Build(ProbeOptions options, CheckRecorder recorder, DateTimeOffset utcNow)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(recorder);
        using var stream = new MemoryStream();
        using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            json.WriteStartObject();
            json.WriteString("schema", Schema);
            json.WriteString("mode", options.Mode == ProbeMode.Live ? "live" : "self-test");
            json.WriteString("scope", options.Mode == ProbeMode.Live
                ? "A real ingress at baseAddress. Only the checks named identity, unary, exact, error, cancel, deadline and target describe it; codec checks are in-process."
                : "In-process fixture only. This is the verifier's own test and says nothing about any real ingress.");
            if (options.BaseAddress is not null)
            {
                json.WriteString("baseAddress", options.BaseAddress.GetLeftPart(UriPartial.Path));
            }

            json.WriteString("utc", utcNow.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture));
            json.WriteStartObject("runtime");
            json.WriteString("framework", RuntimeInformation.FrameworkDescription);
            json.WriteString("os", RuntimeInformation.OSDescription);
            json.WriteString("architecture", RuntimeInformation.ProcessArchitecture.ToString());
            json.WriteBoolean("nativeAot", RuntimeIdentity.IsNativeAot);
            json.WriteString("generatedClient", typeof(HelloService).Assembly.GetName().Name + " " + ClientVersion());
            json.WriteEndObject();
            json.WriteStartArray("checks");
            foreach (var check in recorder.Results)
            {
                json.WriteStartObject();
                json.WriteString("name", check.Name);
                json.WriteBoolean("passed", check.Passed);
                json.WriteString("detail", check.Detail);
                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteString("result", recorder.AllPassed ? "PASS" : "FAIL");
            json.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray()) + "\n";
    }

    public static string ClientVersion() =>
        System.Reflection.CustomAttributeExtensions.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(
            typeof(HelloService).Assembly)?.InformationalVersion ?? "(version attribute not retained)";
}
