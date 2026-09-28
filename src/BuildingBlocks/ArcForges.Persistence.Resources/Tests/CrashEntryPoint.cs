// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Persistence.Resources.Tests;

internal static class CrashEntryPoint
{
    public static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--append-kill")
        {
            if (!AppendStoreTests.LocalKillEnabled) return 2;
            using var stream = new InterruptedFile(args[1], args[4]);
            using var writer = new AppendStore(stream);
            long first = writer.AppendChunk([1, 2, 3]);
            writer.MapSegment(Guid.Parse(args[3]), [new(first, 0, 3)]);
            if (bool.Parse(args[2]))
            {
                stream.InterruptPayload = true;
                writer.AppendChunk(new byte[1024]);
            }
            else stream.AwaitKill();
            return 3; // Reaching here means the parent did not interrupt the child.
        }
        return args.Any(argument => argument is "--server" or "--internal-msbuild-node")
            ? Xunit.MicrosoftTestingPlatform.TestPlatformTestFramework.RunAsync(args, SelfRegisteredExtensions.AddSelfRegisteredExtensions).GetAwaiter().GetResult()
            : Xunit.Runner.InProc.SystemConsole.ConsoleRunner.Run(args).GetAwaiter().GetResult();
    }

    private sealed class InterruptedFile(string path, string ready) : FileStream(path, FileMode.CreateNew,
        FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough)
    {
        internal bool InterruptPayload { get; set; }
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (InterruptPayload && buffer.Length == 1024)
            {
                base.Write(buffer[..400]);
                Flush(flushToDisk: true);
                AwaitKill();
            }
            else base.Write(buffer);
        }
        internal void AwaitKill()
        {
            File.WriteAllText(ready, "actual AppendStore reached interruption boundary");
            _ = Console.ReadLine();
        }
    }
}
