// SPDX-License-Identifier: AGPL-3.0-only

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace ArcForges.Tests.ArchitectureTests;

public sealed class RepositoryPolicyTests
{
    private static readonly string Root = FindRoot();

    [Xunit.Fact]
    public void SolutionsContainOnlyExistingOwnedProjects()
    {
        foreach (string name in new[] { "DesktopPlatform.slnx", "win.slnx" })
        {
            var solution = XDocument.Load(Path.Combine(Root, name));
            foreach (var reference in solution.Descendants("Project"))
            {
                string path = reference.Attribute("Path")!.Value;
                Xunit.Assert.True(File.Exists(Path.Combine(Root, path)), path);
            }
        }

        foreach (string name in new[] { "ArcChat", "ArcNotes", "ArcScope", "ArcSlate", "Cloud", "Web", "Mobile", "Contracts", "SDK" })
        {
            Xunit.Assert.False(Directory.Exists(Path.Combine(Root, "src", name)), name);
        }

        Xunit.Assert.False(File.Exists(Path.Combine(Root, ".gitmodules")));
        Xunit.Assert.False(Directory.Exists(Path.Combine(Root, "native", "arcscope-mdf-abi")));
    }

    [Xunit.Fact]
    public void ProjectReferencesStayInsideThisRepository()
    {
        foreach (string file in Files("*.csproj"))
        {
            foreach (var reference in XDocument.Load(file).Descendants("ProjectReference"))
            {
                string relative = reference.Attribute("Include")!.Value.Replace('\\', Path.DirectorySeparatorChar);
                string target = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(file)!, relative));
                Xunit.Assert.StartsWith(Root + Path.DirectorySeparatorChar, target, StringComparison.OrdinalIgnoreCase);
                Xunit.Assert.True(File.Exists(target), target);
            }
        }
    }

    [Xunit.Fact]
    public void ProductionNativeBindingsHaveOneCapabilityOwner()
    {
        // The closed map: every production binding is one library:entry-point export with exactly one owner directory and exactly its declared
        // marshalling flags (UTF-16 strings, last-error capture). A binding that is not listed, is listed twice or is declared elsewhere fails.
        string image = Path.Combine(Root, "src", "Native", "ArcForges.Native.Image");
        string pdf = Path.Combine(Root, "src", "Native", "ArcForges.Native.Pdf");
        string secrets = Path.Combine(Root, "src", "BuildingBlocks", "ArcForges.Security.Secrets");
        string broker = Path.Combine(Root, "src", "DesktopHelpers", "ArcForges.ContentSandbox.Broker", "Native");
        string helper = Path.Combine(Root, "src", "DesktopHelpers", "ArcForges.ContentSandbox", "Native");
        var expected = new Dictionary<string, (string Owner, bool Utf16, bool LastError)>(StringComparer.Ordinal)
        {
            ["Advapi32.dll:CredDeleteW"] = (secrets, true, true),
            ["Advapi32.dll:CredFree"] = (secrets, false, false),
            ["Advapi32.dll:CredReadW"] = (secrets, true, true),
            ["Advapi32.dll:CredWriteW"] = (secrets, false, true),
            ["ArcImageNative:arc_image_get_abi_version"] = (image, false, false),
            ["ArcImageNative:arc_image_get_build_info"] = (image, false, false),
            ["ArcImageNative:arc_image_get_last_error"] = (image, false, false),
            ["ArcImageNative:arc_image_open"] = (image, false, false),
            ["ArcImageNative:arc_image_read"] = (image, false, false),
            ["ArcImageNative:arc_image_close"] = (image, false, false),
            ["ArcPdfNative:arc_pdf_get_abi_version"] = (pdf, false, false),
            ["ArcPdfNative:arc_pdf_get_build_info"] = (pdf, false, false),
            ["ArcPdfNative:arc_pdf_get_last_error"] = (pdf, false, false),
            ["ArcPdfNative:arc_pdf_open"] = (pdf, false, false),
            ["ArcPdfNative:arc_pdf_page_info"] = (pdf, false, false),
            ["ArcPdfNative:arc_pdf_render"] = (pdf, false, false),
            ["ArcPdfNative:arc_pdf_text"] = (pdf, false, false),
            ["ArcPdfNative:arc_pdf_close"] = (pdf, false, false),
            ["Advapi32.dll:EqualSid"] = (broker, false, false),
            ["Advapi32.dll:FreeSid"] = (broker, false, false),
            ["Advapi32.dll:GetTokenInformation"] = (broker, false, true),
            ["Advapi32.dll:OpenProcessToken"] = (broker, false, true),
            ["Kernel32.dll:AssignProcessToJobObject"] = (broker, false, true),
            ["Kernel32.dll:CloseHandle"] = (broker, false, false),
            ["Kernel32.dll:CreateFileW"] = (broker, true, true),
            ["Kernel32.dll:CreateJobObjectW"] = (broker, false, true),
            ["Kernel32.dll:CreateProcessW"] = (broker, true, true),
            ["Kernel32.dll:DeleteProcThreadAttributeList"] = (broker, false, false),
            ["Kernel32.dll:DuplicateHandle"] = (broker, false, true),
            ["Kernel32.dll:InitializeProcThreadAttributeList"] = (broker, false, true),
            ["Kernel32.dll:IsProcessInJob"] = (broker, false, true),
            ["Kernel32.dll:ResumeThread"] = (broker, false, true),
            ["Kernel32.dll:SetHandleInformation"] = (broker, false, true),
            ["Kernel32.dll:SetInformationJobObject"] = (broker, false, true),
            ["Kernel32.dll:TerminateJobObject"] = (broker, false, true),
            ["Kernel32.dll:TerminateProcess"] = (broker, false, true),
            ["Kernel32.dll:UpdateProcThreadAttribute"] = (broker, false, true),
            ["WinTrust.dll:WinVerifyTrust"] = (broker, false, false),
            ["Userenv.dll:CreateAppContainerProfile"] = (broker, true, false),
            ["Userenv.dll:DeriveAppContainerSidFromAppContainerName"] = (broker, true, false),
            ["libc:close"] = (broker, false, true),
            ["libc:fcntl"] = (broker, false, true),
            ["libc:kill"] = (broker, false, true),
            ["libc:memfd_create"] = (broker, false, true),
            ["libc:posix_spawn"] = (broker, false, false),
            ["libc:posix_spawn_file_actions_adddup2"] = (broker, false, false),
            ["libc:posix_spawn_file_actions_addclosefrom_np"] = (broker, false, false),
            ["libc:posix_spawn_file_actions_destroy"] = (broker, false, false),
            ["libc:posix_spawn_file_actions_init"] = (broker, false, false),
            ["libc:socketpair"] = (broker, false, true),
            ["libc:waitpid"] = (broker, false, true),
            ["Kernel32.dll:MapViewOfFile"] = (helper, false, true),
            ["Kernel32.dll:UnmapViewOfFile"] = (helper, false, true),
            ["libc:getppid"] = (helper, false, false),
            ["libc:prctl"] = (helper, false, true),
            ["libc:setrlimit"] = (helper, false, true),
            ["libc:syscall"] = (helper, false, true),
        };
        var exports = new HashSet<string>(StringComparer.Ordinal);
        foreach (string file in Files("*.cs").Where(file => Path.GetRelativePath(Root, file)
            .Replace('\\', '/').StartsWith("src/", StringComparison.Ordinal)))
        {
            string source = File.ReadAllText(file);
            Xunit.Assert.DoesNotMatch(@"\bDllImport\s*\(", source);
            int declarations = System.Text.RegularExpressions.Regex.Count(source, @"\bLibraryImport\s*\(");
            int matched = 0;
            foreach (System.Text.RegularExpressions.Match match in System.Text.RegularExpressions.Regex.Matches(
                source, """LibraryImport\("([^"]+)", EntryPoint = "([^"]+)"(, StringMarshalling = StringMarshalling\.Utf16)?(, SetLastError = true)?\)"""))
            {
                matched++;
                string key = match.Groups[1].Value + ":" + match.Groups[2].Value;
                Xunit.Assert.True(expected.TryGetValue(key, out var allowed), key);
                Xunit.Assert.Equal(allowed.Owner, Path.GetDirectoryName(file));
                Xunit.Assert.Equal(allowed.Utf16, match.Groups[3].Success);
                Xunit.Assert.Equal(allowed.LastError, match.Groups[4].Success);
                Xunit.Assert.True(exports.Add(key), "Duplicate production binding: " + match.Value);
            }

            Xunit.Assert.Equal(declarations, matched);
        }

        Xunit.Assert.Equal(expected.Keys.Order(StringComparer.Ordinal), exports.OrderBy(value => value, StringComparer.Ordinal));
        foreach (string file in Files("*.csproj").Where(file => Path.GetRelativePath(Root, file)
            .Replace('\\', '/').StartsWith("src/", StringComparison.Ordinal)))
        {
            foreach (var reference in XDocument.Load(file).Descendants("ProjectReference"))
            {
                string target = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(file)!,
                    reference.Attribute("Include")!.Value.Replace('\\', Path.DirectorySeparatorChar)));
                Xunit.Assert.StartsWith(Path.Combine(Root, "src") + Path.DirectorySeparatorChar, target, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    [Xunit.Fact]
    public void PublishedProjectsAreExplicitAndContainNoPlaceholders()
    {
        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "eng", "packaging", "packages.json")));
        var allowed = manifest.RootElement.GetProperty("packages").EnumerateArray()
            .Select(package => Path.GetFullPath(Path.Combine(Root, package.GetProperty("project").GetString()!)))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        Xunit.Assert.NotEmpty(allowed);
        foreach (string file in Files("*.csproj"))
        {
            bool packable = XDocument.Load(file).Descendants("IsPackable").Any(value => value.Value == "true");
            Xunit.Assert.Equal(allowed.Contains(file), packable);
            if (packable)
            {
                Xunit.Assert.Empty(Directory.EnumerateFiles(Path.GetDirectoryName(file)!, "*Placeholder.cs", SearchOption.AllDirectories));
            }
        }
    }

    [Xunit.Fact]
    public void SourceHeadersAndLicenceArePreserved()
    {
        string[] extensions = [".cs", ".csproj", ".cpp", ".h", ".mm", ".props", ".targets", ".vcxproj", ".cmake", ".py"];
        foreach (string file in Files("*").Where(file => extensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase)
            || Path.GetFileName(file) == "CMakeLists.txt"))
        {
            Xunit.Assert.Contains(File.ReadLines(file).Take(5), line => line.Contains("SPDX-License-Identifier:", StringComparison.Ordinal));
        }

        string license = File.ReadAllText(Path.Combine(Root, "LICENSE")).Replace("\r\n", "\n", StringComparison.Ordinal);
        Xunit.Assert.Equal("8486A10C4393CEE1C25392769DDD3B2D6C242D6EC7928E1414EFFF7DFB2F07EF",
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(license))));
    }

    private static IEnumerable<string> Files(string pattern) =>
        Directory.EnumerateFiles(Root, pattern, SearchOption.AllDirectories).Where(path =>
            !Path.GetRelativePath(Root, path).Split(Path.DirectorySeparatorChar)
                .Any(part => part is ".git" or ".worktree" or "artifacts" or "bin" or "obj"));

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "DesktopPlatform.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("DesktopPlatform root not found.");
    }
}
