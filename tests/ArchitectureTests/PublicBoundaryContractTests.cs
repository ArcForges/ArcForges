// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Build.Policy.Architecture;

namespace ArcForges.Tests.ArchitectureTests;

public sealed class PublicBoundaryContractTests
{
    [Xunit.Fact]
    public void ImagePublicContractHasOnlyTypedManagedResults()
    {
        string source = """
            using ArcForges.Native.Abstractions;
            using ArcForges.Native.Image;
            class Consumer {
                NativeAbiVersion Version() => ImageAbi.GetAbiVersion();
                string Build() => ImageAbi.GetBuildInfo();
                NativeError Error() => ImageAbi.GetLastError();
            }
            """;
        _ = FixtureCompiler.Compile("ImageContract", new Dictionary<string, string> { ["consumer.cs"] = source },
            References("ArcForges.Native.Abstractions", "ArcForges.Native.Image"));
        Xunit.Assert.Throws<InvalidOperationException>(() => FixtureCompiler.Compile("InvalidImageContract",
            new Dictionary<string, string> { ["consumer.cs"] = source.Replace("NativeError Error()", "System.IntPtr Error()", StringComparison.Ordinal) },
            References("ArcForges.Native.Abstractions", "ArcForges.Native.Image")));
    }

    [Xunit.Fact]
    public void ProductCodeCannotInstantiateTheInternalImageParser()
    {
        string[] parserTypes = ["IImageInput", "IImageReader", "ImageReader", "ImagePixelFormat", "ImageLimits", "ImageChannel", "ImageMetadata", "ImageNativeException"];
        string source = "using ArcForges.Native.Image; class Consumer { System.Type[] ParserTypes() => [" +
            string.Join(", ", parserTypes.Select(type => "typeof(" + type + ")")) + "]; }";
        var compilation = FixtureCompiler.Create("UntrustedProductImageConsumer", new Dictionary<string, string> { ["consumer.cs"] = source },
            References("ArcForges.Native.Abstractions", "ArcForges.Native.Image"));
        var errors = compilation.GetDiagnostics(Xunit.TestContext.Current.CancellationToken).Where(diagnostic => diagnostic.Severity == Microsoft.CodeAnalysis.DiagnosticSeverity.Error).ToArray();
        Xunit.Assert.Equal(parserTypes.Length, errors.Length);
        Xunit.Assert.All(errors, diagnostic => Xunit.Assert.Equal("CS0122", diagnostic.Id));
        foreach (string parserType in parserTypes)
        {
            Xunit.Assert.Contains(errors, diagnostic => diagnostic.GetMessage(System.Globalization.CultureInfo.InvariantCulture).Contains("'" + parserType + "'", StringComparison.Ordinal));
        }
    }

    [Xunit.Fact]
    public void ApplicationStopContractPreservesCancellationAndTypedOutcome()
    {
        string source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ArcForges.Application.Abstractions;
            using ArcForges.Foundation.Errors;
            class Consumer {
                ValueTask<Outcome<bool>> Stop(IApplicationLifecycle owner, CancellationToken token)
                    => owner.RequestStopAsync(token);
            }
            """;
        _ = FixtureCompiler.Compile("LifecycleContract", new Dictionary<string, string> { ["consumer.cs"] = source },
            References("ArcForges.Application.Abstractions", "ArcForges.Foundation"));
        Xunit.Assert.Throws<InvalidOperationException>(() => FixtureCompiler.Compile("InvalidLifecycleContract",
            new Dictionary<string, string> { ["consumer.cs"] = source.Replace("ValueTask<Outcome<bool>>", "Task<bool>", StringComparison.Ordinal) },
            References("ArcForges.Application.Abstractions", "ArcForges.Foundation")));
    }

    private static IEnumerable<string> References(params string[] names)
    {
        string directory = AppContext.BaseDirectory;
        var framework = new DirectoryInfo(directory);
        string hostRoot = framework.Parent!.Parent!.Parent!.FullName;
        return names.Select(name => Path.Combine(hostRoot, name, "Release", "net10.0", name + ".dll"));
    }
}
