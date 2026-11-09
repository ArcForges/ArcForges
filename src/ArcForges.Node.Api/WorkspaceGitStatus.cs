// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Api;

/// <summary>
/// Inspects a restricted Git repository directly through checked workspace handles, without executing Git, hooks,
/// filters or config includes. Unsupported formats and unverified states are explicitly UNKNOWN. This is an internal
/// implementation slice, not a claim that every Git repository format or workspace service is delivered.
/// </summary>
internal static class WorkspaceGitStatus
{
    private const int MaximumEntries = 10_000;
    private const long MaximumBytes = 16 * 1024 * 1024;
    private const int MaximumObject = 8 * 1024 * 1024;
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(2);
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly SemaphoreSlim Workers = new(4, 4);

    internal static Task<GitStatusSummary?> ObserveAsync(WorkspacePath root, CancellationToken cancellationToken = default) =>
        ObserveAsync(root, sources: null, cancellationToken);

    // A test may point to isolated, actual on-disk configuration sources. Production passes null and discovers
    // the host's applicable sources; no callback may assert a synthetic configuration result.
    internal static async Task<GitStatusSummary?> ObserveAsync(WorkspacePath root, GitConfigSources? sources, CancellationToken cancellationToken,
        Action<string>? failureForTests = null)
    {
        ArgumentNullException.ThrowIfNull(root);
        cancellationToken.ThrowIfCancellationRequested();
        var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Deadline);
        try
        {
            // Waiting for a worker shares the same two-second budget as the actual inspection.
            await Workers.WaitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            timeout.Dispose();
            failureForTests?.Invoke("worker_wait_timeout");
            return Unknown();
        }
        catch
        {
            timeout.Dispose();
            throw;
        }

        Task<GitStatusSummary?> task;
        try
        {
            var path = root.RootPath;
            var identity = root.RootIdentity with { InstanceToken = root.RootIdentity.InstanceToken.ToArray() };
            task = Task.Run(() =>
            {
                try
                {
                    using var opened = WorkspacePath.OpenRoot(path, identity);
                    return Compute(opened, sources, failureForTests, timeout.Token);
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    failureForTests?.Invoke("open/" + exception.GetType().Name);
                    return Unknown();
                }
                finally
                {
                    Workers.Release();
                }
            });
        }
        catch
        {
            timeout.Dispose();
            Workers.Release();
            throw;
        }

        try
        {
            var result = await task.WaitAsync(timeout.Token).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            failureForTests?.Invoke("inspection_deadline");
            return Unknown();
        }
        finally
        {
            // A blocked native read may outlive the caller's deadline. Its worker owns its separate root handle,
            // remains bounded by the semaphore, and disposes the cancellation source once it actually ends.
            _ = task.ContinueWith(static (_, state) => ((CancellationTokenSource)state!).Dispose(), timeout,
                CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    private static GitStatusSummary? Compute(WorkspacePath root, GitConfigSources? sources, Action<string>? failureForTests,
        CancellationToken cancellationToken)
    {
        var stage = "discovery";
        try
        {
            var context = new Context(root, sources?.AfterReadForTests, cancellationToken);
            if (!HasGitDirectory(root))
            {
                // Git discovers ancestor repositories. Only call the root non-Git after every ancestor was safely
                // checked; an ancestor Git directory, an inaccessible parent or an ambiguous .git file is UNKNOWN.
                var observed = new List<(string Path, WorkspaceObjectIdentity Identity, WorkspaceFileStamp Stamp)>();
                void RecordAbsent(WorkspacePath directory)
                {
                    using var handle = directory.OpenDirectoryForEnumeration("");
                    var stamp = WorkspacePath.FileStamp(handle);
                    if (HasGitDirectory(directory) || stamp != WorkspacePath.FileStamp(handle))
                    {
                        throw new UnknownGitException();
                    }

                    observed.Add((directory.RootPath, directory.RootIdentity, stamp));
                }

                RecordAbsent(root);
                var parent = Path.GetDirectoryName(root.RootPath);
                var depth = 0;
                while (parent is not null)
                {
                    context.Check();
                    if (++depth > 128)
                    {
                        throw new UnknownGitException();
                    }

                    using var ancestor = WorkspacePath.OpenRoot(parent);
                    RecordAbsent(ancestor);
                    parent = Path.GetDirectoryName(parent);
                }

                // This detects observable replacement or namespace changes; it is not a same-user namespace lock.
                foreach (var item in observed)
                {
                    context.Check();
                    using var checkedDirectory = WorkspacePath.OpenRoot(item.Path, item.Identity);
                    using var handle = checkedDirectory.OpenDirectoryForEnumeration("");
                    if (WorkspacePath.FileStamp(handle) != item.Stamp || HasGitDirectory(checkedDirectory))
                    {
                        throw new UnknownGitException();
                    }
                }

                return null;
            }

            stage = "configuration";
            var configuration = ReadConfiguration(context, sources ?? DiscoverSources());
            RejectMeaningfulOptional(context, ".git/info/exclude");
            RejectMeaningfulOptional(context, ".git/info/attributes");
            stage = "head";
            var (head, branch) = ReadHead(context);
            stage = "index";
            var index = ReadIndex(context);
            stage = "objects";
            var objects = new ObjectReader(context);
            var commit = objects.Read(head, "commit");
            var tree = CommitTree(commit);
            var headEntries = new Dictionary<string, Entry>(StringComparer.Ordinal);
            ReadTree(objects, tree, "", headEntries, context, 0);
            foreach (var entry in index.Values.Concat(headEntries.Values))
            {
                _ = objects.Read(entry.Hash, "blob");
            }

            var modified = new HashSet<string>(StringComparer.Ordinal);
            foreach (var pair in index)
            {
                if (!headEntries.TryGetValue(pair.Key, out var old) || old.Mode != pair.Value.Mode ||
                    !old.Hash.AsSpan().SequenceEqual(pair.Value.Hash))
                {
                    modified.Add(pair.Key);
                }
            }

            foreach (var path in headEntries.Keys)
            {
                if (!index.ContainsKey(path))
                {
                    modified.Add(path);
                }
            }

            var found = new HashSet<string>(StringComparer.Ordinal);
            stage = "worktree";
            uint untracked = 0;
            long untrackedBytes = 0;
            Scan(context, "", index, found, modified, configuration, ref untracked, ref untrackedBytes, 0);
            foreach (var path in index.Keys)
            {
                if (!found.Contains(path))
                {
                    modified.Add(path);
                }
            }

            // The status framing is porcelain-v1 -z with rename detection disabled: two status bytes, one space,
            // UTF-8 path and a NUL. The parser does not emit this text; the bound prevents returning misleading counts
            // after a status that would exceed the specified 16 KiB observation budget.
            var statusBytes = untrackedBytes + modified.Sum(path => 4L + StrictUtf8.GetByteCount(path));
            if (statusBytes > 16_384)
            {
                throw new TruncatedGitException();
            }

            // A single exact spelling of index.lock means locked. Windows ambiguous case variants are UNKNOWN.
            context.TrackDirectory(".git");
            var gitDirectory = WorkspaceDirectoryEntries.Read(root, ".git", MaximumEntries, cancellationToken);
            if (gitDirectory.Truncated)
            {
                throw new UnknownGitException();
            }

            if (OperatingSystem.IsWindows() && gitDirectory.Names.Any(name =>
                name.Equals("index.lock", StringComparison.OrdinalIgnoreCase) && name != "index.lock"))
            {
                throw new UnknownGitException();
            }

            var result = new GitStatusSummary
            {
                Quality = GitStatusQuality.Complete,
                Head = Convert.ToHexStringLower(head),
                Dirty = modified.Count != 0 || untracked != 0,
                ModifiedFiles = checked((uint)modified.Count),
                UntrackedFiles = untracked,
                Locked = gitDirectory.Names.Contains("index.lock", StringComparer.Ordinal),
            };
            if (branch is not null)
            {
                result.Branch = branch;
            }

            stage = "revalidation";
            context.VerifyStable();
            context.Check();
            return result;
        }
        catch (TruncatedGitException)
        {
            return new GitStatusSummary { Quality = GitStatusQuality.Truncated };
        }
        catch (Exception exception) when (exception is UnknownGitException or IOException or UnauthorizedAccessException or OverflowException or OperationCanceledException or ArgumentException)
        {
            // Tests receive only a fixed phase, exception type and closed native reason, never a path or file/config text.
            var reason = exception is WorkspacePathException native ? native.Reason : exception.GetType().Name;
            failureForTests?.Invoke(stage + "/" + reason);
            return Unknown();
        }
    }

    private static GitStatusSummary Unknown() => new() { Quality = GitStatusQuality.Unknown };

    private static bool HasGitDirectory(WorkspacePath root)
    {
        try
        {
            using var handle = root.OpenDirectory(".git");
            return true;
        }
        catch (WorkspacePathException exception) when (exception.Reason is "native_2" or "native_3")
        {
            return false;
        }
    }

    internal sealed record GitConfigSources(IReadOnlyList<string> ConfigPaths, string? IgnorePath, string? AttributesPath,
        Action<string>? AfterReadForTests = null);

    private sealed class Configuration
    {
        internal bool FileMode { get; set; } = true;
        internal bool IgnoreCase { get; set; }
    }

    private sealed record Entry(uint Mode, byte[] Hash);

    private static GitConfigSources DiscoverSources()
    {
        // Environment-based repository redirects or injected config make a comparison of this root ambiguous.
        foreach (var name in (string[])["GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_DIR", "GIT_WORK_TREE",
            "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR"])
        {
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(name)))
            {
                throw new UnknownGitException();
            }
        }

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!Path.IsPathFullyQualified(home))
        {
            throw new UnknownGitException();
        }

        var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        if (string.IsNullOrEmpty(xdg))
        {
            xdg = Path.Combine(home, ".config");
        }

        if (!Path.IsPathFullyQualified(xdg))
        {
            throw new UnknownGitException();
        }

        var configs = new List<string>();
        var noSystem = Environment.GetEnvironmentVariable("GIT_CONFIG_NOSYSTEM");
        if (string.IsNullOrEmpty(noSystem) || !Boolean(noSystem))
        {
            var specified = Environment.GetEnvironmentVariable("GIT_CONFIG_SYSTEM");
            if (!string.IsNullOrEmpty(specified))
            {
                // Do not open an arbitrary environment-selected file, which may contain unrelated secrets.
                throw new UnknownGitException();
            }
            else if (OperatingSystem.IsLinux())
            {
                // Git's normal system location on the supported Linux distribution.
                configs.Add("/etc/gitconfig");
            }
            else
            {
                // The native Windows validation must verify this installation's system config location.
                var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                if (!Path.IsPathFullyQualified(programFiles)) throw new UnknownGitException();
                configs.Add(Path.Combine(programFiles, "Git", "etc", "gitconfig"));
            }
        }

        var global = Environment.GetEnvironmentVariable("GIT_CONFIG_GLOBAL");
        if (!string.IsNullOrEmpty(global))
        {
            if (global != "/dev/null" && !global.Equals("NUL", StringComparison.OrdinalIgnoreCase))
            {
                // Only the explicit null device is recognized; never open an arbitrary environment-selected file.
                throw new UnknownGitException();
            }
        }
        else
        {
            configs.Add(Path.Combine(xdg, "git", "config"));
            configs.Add(Path.Combine(home, ".gitconfig"));
        }

        return new GitConfigSources(configs, Path.Combine(xdg, "git", "ignore"), Path.Combine(xdg, "git", "attributes"));
    }

    private static Configuration ReadConfiguration(Context context, GitConfigSources sources)
    {
        var result = new Configuration();
        foreach (var path in sources.ConfigPaths)
        {
            if (context.ReadExternalOptional(path, 65_536) is { } data)
            {
                try
                {
                    ApplyConfiguration(context, result, data);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(data);
                }
            }
        }

        if (context.ReadOptional(".git/config", 65_536) is { } local)
        {
            try
            {
                ApplyConfiguration(context, result, local);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(local);
            }
        }

        if (sources.IgnorePath is { } ignore && context.ReadExternalOptional(ignore, 65_536) is { } ignoreBytes)
        {
            try { RejectMeaningful(ignoreBytes); }
            finally { CryptographicOperations.ZeroMemory(ignoreBytes); }
        }

        if (sources.AttributesPath is { } attributes && context.ReadExternalOptional(attributes, 65_536) is { } attributeBytes)
        {
            try { RejectMeaningful(attributeBytes); }
            finally { CryptographicOperations.ZeroMemory(attributeBytes); }
        }

        if (OperatingSystem.IsWindows() && result.FileMode)
        {
            throw new UnknownGitException();
        }

        return result;
    }

    private static void ApplyConfiguration(Context context, Configuration configuration, byte[] data)
    {
        string? section = null;
        var offset = 0;
        while (offset < data.Length)
        {
            context.Check();
            var rest = data.AsSpan(offset);
            var newline = rest.IndexOf((byte)'\n');
            var line = Trim(newline < 0 ? rest : rest[..newline]);
            offset += newline < 0 ? rest.Length : newline + 1;
            if (line.IsEmpty || line[0] is (byte)'#' or (byte)';')
            {
                continue;
            }

            if (line[0] == '[')
            {
                if (line[^1] != ']') throw new UnknownGitException();
                var header = Trim(line[1..^1]);
                var space = header.IndexOfAny((byte)' ', (byte)'\t');
                CheckConfigSection(header, space);
                var token = space < 0 ? header : header[..space];
                section = Encoding.ASCII.GetString(token).ToLowerInvariant();
                if (section is "include" or "includeif" or "filter" or "extensions")
                {
                    throw new UnknownGitException();
                }

                continue;
            }

            if (section is null)
            {
                throw new UnknownGitException();
            }

            CheckConfigAssignment(line);
            if (section != "core")
            {
                // Do not decode values of unrelated user, credential or remote settings, and never log them.
                continue;
            }

            var equals = line.IndexOf((byte)'=');
            if (equals <= 0)
            {
                throw new UnknownGitException();
            }

            var key = Encoding.ASCII.GetString(Trim(line[..equals])).ToLowerInvariant();
            var valueBytes = Trim(line[(equals + 1)..]);
            switch (key)
            {
                case "repositoryformatversion":
                    if (!valueBytes.SequenceEqual("0"u8)) throw new UnknownGitException();
                    break;
                case "filemode":
                    configuration.FileMode = Boolean(Encoding.ASCII.GetString(valueBytes));
                    break;
                case "ignorecase":
                    configuration.IgnoreCase = Boolean(Encoding.ASCII.GetString(valueBytes));
                    break;
                case "bare":
                    if (Boolean(Encoding.ASCII.GetString(valueBytes))) throw new UnknownGitException();
                    break;
                case "logallrefupdates":
                case "symlinks":
                case "precomposeunicode":
                    _ = Boolean(Encoding.ASCII.GetString(valueBytes));
                    break;
                case "fsmonitor":
                case "autocrlf":
                    if (Boolean(Encoding.ASCII.GetString(valueBytes))) throw new UnknownGitException();
                    break;
                default:
                    // This includes excludesfile, attributesfile and worktree redirection: no outside path is followed.
                    throw new UnknownGitException();
            }
        }
    }

    // Validate structure directly on bytes; unrelated credential/user values are never decoded, retained or logged.
    // Git permits continuations and some header suffixes that this bounded parser does not interpret: refuse them.
    private static void CheckConfigSection(ReadOnlySpan<byte> header, int space)
    {
        var token = space < 0 ? header : header[..space];
        if (token.IsEmpty) throw new UnknownGitException();
        foreach (var c in token)
            if (!IsAsciiLetter(c) && !IsAsciiDigit(c) && c != 45 && c != 46) throw new UnknownGitException();

        if (space < 0) return;
        var subsection = Trim(header[space..]);
        if (subsection.Length < 2 || subsection[0] != '"' || subsection[^1] != '"') throw new UnknownGitException();
        var escaped = false;
        for (var i = 1; i < subsection.Length - 1; i++)
        {
            var c = subsection[i];
            if (c == 0) throw new UnknownGitException();
            if (escaped) { escaped = false; continue; }
            if (c == 92) escaped = true;
            else if (c == '"') throw new UnknownGitException();
        }

        if (escaped) throw new UnknownGitException();
        if (Encoding.ASCII.GetString(token).Equals("core", StringComparison.OrdinalIgnoreCase))
            throw new UnknownGitException(); // A subsection is not the core settings namespace.
    }

    private static void CheckConfigAssignment(ReadOnlySpan<byte> line)
    {
        var equals = line.IndexOf((byte)'=');
        var name = equals < 0 ? line : line[..equals];
        if (equals < 0)
        {
            var comment = name.IndexOfAny((byte)'#', (byte)';');
            if (comment >= 0) name = name[..comment];
        }

        name = Trim(name);
        if (name.IsEmpty || !IsAsciiLetter(name[0])) throw new UnknownGitException();
        foreach (var c in name[1..])
            if (!IsAsciiLetter(c) && !IsAsciiDigit(c) && c != '-') throw new UnknownGitException();

        if (equals < 0) return;
        var quoted = false;
        var escaped = false;
        foreach (var c in line[(equals + 1)..])
        {
            if (c == 0) throw new UnknownGitException();
            if (escaped)
            {
                if (c is not (110 or 116 or 98 or 92 or 34)) throw new UnknownGitException();
                escaped = false;
            }
            else if (c == 92) escaped = true;
            else if (c == '"') quoted = !quoted;
            else if (!quoted && (c == 35 || c == 59)) break;
        }

        if (quoted || escaped) throw new UnknownGitException();
    }

    private static bool IsAsciiLetter(byte c) => c is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z';
    private static bool IsAsciiDigit(byte c) => c is >= (byte)'0' and <= (byte)'9';

    private static ReadOnlySpan<byte> Trim(ReadOnlySpan<byte> value)
    {
        while (!value.IsEmpty && value[0] is (byte)' ' or (byte)'\t' or (byte)'\r') value = value[1..];
        while (!value.IsEmpty && value[^1] is (byte)' ' or (byte)'\t' or (byte)'\r') value = value[..^1];
        return value;
    }

    private static bool Boolean(string value) => value.ToLowerInvariant() switch
    {
        "true" or "yes" or "on" or "1" => true,
        "false" or "no" or "off" or "0" => false,
        _ => throw new UnknownGitException(),
    };

    private static void RejectMeaningfulOptional(Context context, string path)
    {
        if (context.ReadOptional(path, 65_536) is { } data)
        {
            try { RejectMeaningful(data); }
            finally { CryptographicOperations.ZeroMemory(data); }
        }
    }

    private static void RejectMeaningful(byte[] data)
    {
        var offset = 0;
        while (offset < data.Length)
        {
            var rest = data.AsSpan(offset);
            var newline = rest.IndexOf((byte)'\n');
            var line = Trim(newline < 0 ? rest : rest[..newline]);
            offset += newline < 0 ? rest.Length : newline + 1;
            if (!line.IsEmpty && line[0] != '#') throw new UnknownGitException();
        }
    }

    private static (byte[] Head, string? Branch) ReadHead(Context context)
    {
        var text = Text(context.Read(".git/HEAD", 4096)).Trim();
        string? branch = null;
        if (text.StartsWith("ref: ", StringComparison.Ordinal))
        {
            var reference = text[5..];
            if (!reference.StartsWith("refs/heads/", StringComparison.Ordinal) || reference.Length == 11)
            {
                throw new UnknownGitException();
            }

            _ = WorkspacePath.Components(reference);
            branch = reference[11..];
            var loose = context.ReadOptional(".git/" + reference, 4096);
            if (loose is not null)
            {
                text = Text(loose).Trim();
            }
            else if (context.ReadOptional(".git/packed-refs", 65_536) is { } packed)
            {
                var matches = Text(packed).Split('\n').Select(line => line.Trim()).Where(line =>
                    line.Length == 41 + reference.Length && line[40] == ' ' && line[41..] == reference).ToArray();
                if (matches.Length != 1)
                {
                    throw new UnknownGitException();
                }

                text = matches[0][..40];
            }
            else
            {
                throw new UnknownGitException();
            }
        }

        return (Hash(text), branch);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350", Justification =
        "Git index v2/v3 specifies SHA-1; this checks format compatibility, not authorization or collision-resistant authenticity.")]
    private static Dictionary<string, Entry> ReadIndex(Context context)
    {
        var data = context.Read(".git/index", MaximumObject);
        if (data.Length < 32 || !data.AsSpan(0, 4).SequenceEqual("DIRC"u8) ||
            !CryptographicOperations.FixedTimeEquals(SHA1.HashData(data.AsSpan(0, data.Length - 20)), data.AsSpan(data.Length - 20)))
        {
            throw new UnknownGitException();
        }

        var version = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(4, 4));
        var count = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(8, 4));
        if (version is not (2 or 3) || count > MaximumEntries)
        {
            throw new UnknownGitException();
        }

        var result = new Dictionary<string, Entry>(StringComparer.Ordinal);
        var end = data.Length - 20;
        var offset = 12;
        for (uint i = 0; i < count; i++)
        {
            context.Check();
            if (offset > end - 63)
            {
                throw new UnknownGitException();
            }

            var mode = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset + 24, 4));
            var flags = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset + 60, 2));
            if (mode is not (0x81A4u or 0x81EDu) || (flags & 0xF000) != 0)
            {
                throw new UnknownGitException();
            }

            var nameStart = offset + 62;
            var terminator = Array.IndexOf(data, (byte)0, nameStart, end - nameStart);
            if (terminator < 0)
            {
                throw new UnknownGitException();
            }

            var name = StrictUtf8.GetString(data, nameStart, terminator - nameStart);
            _ = WorkspacePath.Components(name);
            var nameLength = terminator - nameStart;
            if ((flags & 0x0FFF) != Math.Min(nameLength, 0x0FFF) ||
                !result.TryAdd(name, new Entry(mode, data.AsSpan(offset + 40, 20).ToArray())))
            {
                throw new UnknownGitException();
            }

            var length = checked((62 + nameLength + 1 + 7) & ~7);
            if (length > end - offset || data.AsSpan(terminator, offset + length - terminator).IndexOfAnyExcept((byte)0) >= 0)
            {
                throw new UnknownGitException();
            }

            offset += length;
        }

        // Unknown lower-case extensions are mandatory and cannot be ignored. Upper-case extensions are optional
        // Git index accelerators; this implementation independently traverses the whole worktree.
        while (offset < end)
        {
            if (offset > end - 8 || data[offset] is < (byte)'A' or > (byte)'Z')
            {
                throw new UnknownGitException();
            }

            var length = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset + 4, 4));
            if (length > end - offset - 8)
            {
                throw new UnknownGitException();
            }

            offset += 8 + checked((int)length);
        }

        return result;
    }

    private static byte[] CommitTree(byte[] data)
    {
        var newline = Array.IndexOf(data, (byte)'\n');
        if (newline != 45 || !data.AsSpan(0, 5).SequenceEqual("tree "u8))
        {
            throw new UnknownGitException();
        }

        return Hash(Encoding.ASCII.GetString(data, 5, 40));
    }

    private static void ReadTree(ObjectReader objects, byte[] hash, string prefix, Dictionary<string, Entry> entries, Context context, int depth)
    {
        if (depth > 128)
        {
            throw new UnknownGitException();
        }

        var data = objects.Read(hash, "tree");
        var offset = 0;
        while (offset < data.Length)
        {
            context.Check();
            var space = Array.IndexOf(data, (byte)' ', offset);
            var nul = space < 0 ? -1 : Array.IndexOf(data, (byte)0, space + 1);
            if (space <= offset || nul <= space + 1 || nul > data.Length - 21)
            {
                throw new UnknownGitException();
            }

            var modeText = Encoding.ASCII.GetString(data, offset, space - offset);
            var name = StrictUtf8.GetString(data, space + 1, nul - space - 1);
            _ = WorkspacePath.Components(name);
            var path = prefix.Length == 0 ? name : prefix + "/" + name;
            var objectHash = data.AsSpan(nul + 1, 20).ToArray();
            if (modeText is "40000" or "040000")
            {
                ReadTree(objects, objectHash, path, entries, context, depth + 1);
            }
            else
            {
                var mode = modeText switch { "100644" => 0x81A4u, "100755" => 0x81EDu, _ => throw new UnknownGitException() };
                if (entries.Count == MaximumEntries || !entries.TryAdd(path, new Entry(mode, objectHash)))
                {
                    throw new UnknownGitException();
                }
            }

            offset = nul + 21;
        }
    }

    private static void Scan(Context context, string directory, Dictionary<string, Entry> index, HashSet<string> found,
        HashSet<string> modified, Configuration configuration, ref uint untracked, ref long untrackedBytes, int depth)
    {
        if (depth > 128)
        {
            throw new UnknownGitException();
        }

        var remaining = MaximumEntries - context.Entries;
        if (remaining <= 0)
        {
            throw new UnknownGitException();
        }

        context.TrackDirectory(directory);
        var page = WorkspaceDirectoryEntries.Read(context.Root, directory, remaining, context.Token);
        if (page.Truncated)
        {
            throw new UnknownGitException();
        }

        context.Entries += page.Names.Count;
        foreach (var name in page.Names)
        {
            context.Check();
            if (directory.Length == 0 && name == ".git")
            {
                continue;
            }

            if (name == ".git")
            {
                throw new UnknownGitException();
            }

            var path = directory.Length == 0 ? name : directory + "/" + name;
            if (name is ".gitignore" or ".gitattributes")
            {
                RejectMeaningfulOptional(context, path);
            }

            try
            {
                using var child = context.Root.OpenDirectory(path);
                Scan(context, path, index, found, modified, configuration, ref untracked, ref untrackedBytes, depth + 1);
                continue;
            }
            catch (WorkspacePathException exception) when (exception.Reason is "native_20" or "native_267" or "path_link_or_special")
            {
                // Not a directory. It must still pass the verified regular, single-link open below.
            }

            using var file = context.Root.OpenRead(path);
            context.TrackFile(path, file);
            if (configuration.IgnoreCase && !index.ContainsKey(path) &&
                index.Keys.Any(candidate => candidate.Equals(path, StringComparison.OrdinalIgnoreCase)))
            {
                // Avoid guessing case-sensitive directory semantics or reporting an alias as untracked.
                throw new UnknownGitException();
            }

            if (index.TryGetValue(path, out var entry))
            {
                found.Add(path);
                var bytes = context.Read(file, MaximumObject);
                var actual = BlobHash(bytes);
                var identity = WorkspacePath.Identity(file);
                var executable = (identity.Mode & 0x49) != 0;
                if (!actual.AsSpan().SequenceEqual(entry.Hash) ||
                    configuration.FileMode && executable != (entry.Mode == 0x81EDu))
                {
                    modified.Add(path);
                }
            }
            else
            {
                untracked = checked(untracked + 1);
                untrackedBytes = checked(untrackedBytes + 4 + StrictUtf8.GetByteCount(path));
            }
        }
    }

    private static byte[] BlobHash(byte[] bytes)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        hash.AppendData(Encoding.ASCII.GetBytes("blob " + bytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\0"));
        hash.AppendData(bytes);
        return hash.GetHashAndReset();
    }

    private static byte[] Hash(string text)
    {
        if (text.Length != 40 || text.Any(character => !char.IsAsciiHexDigit(character)))
        {
            throw new UnknownGitException();
        }

        return Convert.FromHexString(text);
    }

    private static string Text(byte[] bytes) => StrictUtf8.GetString(bytes);

    private sealed class ObjectReader(Context context)
    {
        private readonly Dictionary<string, (string Type, byte[] Body)> _cache = new(StringComparer.Ordinal);

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350", Justification =
            "Legacy Git loose object IDs specify SHA-1; this is format compatibility, not a security identity or authenticity check.")]
        internal byte[] Read(byte[] hash, string expected)
        {
            var name = Convert.ToHexStringLower(hash);
            if (!_cache.TryGetValue(name, out var value))
            {
                var compressed = context.ReadOptional(".git/objects/" + name[..2] + "/" + name[2..], MaximumObject)
                    ?? throw new UnknownGitException(); // packed or alternate object stores are not supported here.
                using var input = new MemoryStream(compressed, writable: false);
                using var inflater = new ZLibStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                var buffer = new byte[16_384];
                while (true)
                {
                    context.Check();
                    var count = inflater.Read(buffer);
                    if (count == 0) break;
                    context.Consume(count);
                    if (output.Length + count > MaximumObject) throw new UnknownGitException();
                    output.Write(buffer, 0, count);
                }

                var raw = output.ToArray();
                if (!CryptographicOperations.FixedTimeEquals(SHA1.HashData(raw), hash))
                {
                    throw new UnknownGitException();
                }

                var zero = Array.IndexOf(raw, (byte)0);
                if (zero <= 0)
                {
                    throw new UnknownGitException();
                }

                var header = Encoding.ASCII.GetString(raw, 0, zero);
                var separator = header.IndexOf(' ');
                if (separator <= 0 || !int.TryParse(header[(separator + 1)..], System.Globalization.NumberStyles.None,
                        System.Globalization.CultureInfo.InvariantCulture, out var length) || length != raw.Length - zero - 1)
                {
                    throw new UnknownGitException();
                }

                value = (header[..separator], raw[(zero + 1)..]);
                _cache.Add(name, value);
            }

            return value.Type == expected ? value.Body : throw new UnknownGitException();
        }
    }

    private sealed class Context(WorkspacePath root, Action<string>? afterReadForTests, CancellationToken token)
    {
        private readonly long _started = Stopwatch.GetTimestamp();
        private readonly Dictionary<string, FileObservation?> _workspaceFiles = new(StringComparer.Ordinal);
        private readonly Dictionary<string, FileObservation?> _externalFiles = new(StringComparer.Ordinal);
        private readonly Dictionary<string, FileObservation> _directories = new(StringComparer.Ordinal);
        private long _bytes;
        internal WorkspacePath Root { get; } = root;
        internal CancellationToken Token { get; } = token;
        internal int Entries { get; set; }

        internal void Check()
        {
            Token.ThrowIfCancellationRequested();
            if (Stopwatch.GetElapsedTime(_started) > Deadline)
            {
                throw new UnknownGitException();
            }
        }

        internal void Consume(long count)
        {
            _bytes = checked(_bytes + count);
            if (_bytes > MaximumBytes)
            {
                throw new UnknownGitException();
            }
        }

        internal byte[] Read(string path, int maximum) => ReadOptional(path, maximum) ?? throw new UnknownGitException();

        internal byte[]? ReadOptional(string path, int maximum)
        {
            try
            {
                using var file = Root.OpenRead(path);
                TrackFile(path, file);
                var bytes = Read(file, maximum);
                afterReadForTests?.Invoke(path);
                TrackFile(path, file);
                return bytes;
            }
            catch (WorkspacePathException exception) when (exception.Reason is "native_2" or "native_3")
            {
                Remember(_workspaceFiles, path, null);
                return null;
            }
        }

        internal byte[]? ReadExternalOptional(string path, int maximum)
        {
            if (!Path.IsPathFullyQualified(path) || Path.GetDirectoryName(path) is not { } parent || Path.GetFileName(path) is not { Length: > 0 } name)
            {
                throw new UnknownGitException();
            }

            try
            {
                using var anchor = WorkspacePath.OpenRoot(parent);
                using var file = anchor.OpenRead(name);
                Remember(_externalFiles, path, Observe(file));
                var bytes = Read(file, maximum);
                afterReadForTests?.Invoke(path);
                Remember(_externalFiles, path, Observe(file));
                return bytes;
            }
            catch (WorkspacePathException exception) when (exception.Reason is "native_2" or "native_3")
            {
                Remember(_externalFiles, path, null);
                return null;
            }
        }

        internal void TrackFile(string path, SafeFileHandle file) => Remember(_workspaceFiles, path, Observe(file));

        private static void Remember(Dictionary<string, FileObservation?> observations, string path, FileObservation? observation)
        {
            if (observations.TryGetValue(path, out var previous))
            {
                if (previous is null && observation is null) return;
                if (previous is null || observation is null || !previous.Matches(observation)) throw new UnknownGitException();
                return;
            }

            observations.Add(path, observation);
        }

        internal void TrackDirectory(string path)
        {
            using var directory = Root.OpenDirectoryForEnumeration(path);
            var observation = Observe(directory);
            if (_directories.TryGetValue(path, out var previous) && !previous.Matches(observation)) throw new UnknownGitException();
            _directories[path] = observation;
        }

        internal void VerifyStable()
        {
            Check();
            using var reopenedRoot = WorkspacePath.OpenRoot(Root.RootPath, Root.RootIdentity);
            foreach (var pair in _directories)
            {
                Check();
                using var directory = Root.OpenDirectoryForEnumeration(pair.Key);
                if (!pair.Value.Matches(Observe(directory))) throw new UnknownGitException();
            }

            foreach (var pair in _workspaceFiles)
            {
                Check();
                try
                {
                    using var file = Root.OpenRead(pair.Key);
                    if (pair.Value is null || !pair.Value.Matches(Observe(file))) throw new UnknownGitException();
                }
                catch (WorkspacePathException exception) when (exception.Reason is "native_2" or "native_3")
                {
                    if (pair.Value is not null) throw new UnknownGitException();
                }
            }

            foreach (var pair in _externalFiles)
            {
                Check();
                if (Path.GetDirectoryName(pair.Key) is not { } parent || Path.GetFileName(pair.Key) is not { Length: > 0 } name)
                    throw new UnknownGitException();
                try
                {
                    using var anchor = WorkspacePath.OpenRoot(parent);
                    using var file = anchor.OpenRead(name);
                    if (pair.Value is null || !pair.Value.Matches(Observe(file))) throw new UnknownGitException();
                }
                catch (WorkspacePathException exception) when (exception.Reason is "native_2" or "native_3")
                {
                    if (pair.Value is not null) throw new UnknownGitException();
                }
            }
        }

        private static FileObservation Observe(SafeFileHandle file) =>
            new(WorkspacePath.Identity(file), WorkspacePath.FileStamp(file));

        internal byte[] Read(SafeFileHandle file, int maximum)
        {
            Check();
            var identity = WorkspacePath.Identity(file);
            var stamp = WorkspacePath.FileStamp(file);
            if (!identity.IsFile || identity.Links != 1 || stamp.Size < 0)
            {
                throw new UnknownGitException();
            }

            if (stamp.Size > maximum)
            {
                throw new UnknownGitException();
            }

            Consume(stamp.Size);
            var data = new byte[checked((int)stamp.Size)];
            var offset = 0;
            while (offset < data.Length)
            {
                Check();
                var count = RandomAccess.Read(file, data.AsSpan(offset, Math.Min(16_384, data.Length - offset)), offset);
                if (count == 0)
                {
                    throw new UnknownGitException();
                }

                offset += count;
            }

            Check();
            if (WorkspacePath.FileStamp(file) != stamp || !WorkspacePath.Identity(file).SameObject(identity))
            {
                throw new UnknownGitException();
            }

            return data;
        }
    }

    private sealed record FileObservation(WorkspaceObjectIdentity Identity, WorkspaceFileStamp Stamp)
    {
        internal bool Matches(FileObservation other) =>
            Identity.SameObject(other.Identity) && Identity.Mode == other.Identity.Mode &&
            Identity.Links == other.Identity.Links && Stamp == other.Stamp;
    }

    private sealed class UnknownGitException : Exception;
    private sealed class TruncatedGitException : Exception;
}
