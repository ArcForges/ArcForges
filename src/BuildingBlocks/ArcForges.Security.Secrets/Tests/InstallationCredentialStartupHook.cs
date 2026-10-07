// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Security.Secrets;

/// <summary>Owned explicit Windows diagnostic child; normal test execution never enters this hook mode.</summary>
[SuppressMessage("Design", "CA1050", Justification = "DOTNET_STARTUP_HOOKS requires the exact global StartupHook type; this is an opt-in test executable, never a library API.")]
internal static class StartupHook
{
    [SuppressMessage("Design", "CA1031", Justification = "An owned diagnostic child reports only its exception type and exit code; no raw secret or exception payload escapes.")]
    [SuppressMessage("Globalization", "CA1303", Justification = "HELD is a closed machine diagnostic marker, not product UI text.")]
    public static void Initialize()
    {
        var mode = Environment.GetEnvironmentVariable("ARCFORGES_INSTALLATION_CREDENTIAL_CHILD");
        if (mode is null) return;
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("ARCFORGES_LOCAL_OS_SECRET_STORE") != "1"
            || Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true") Environment.Exit(2);
        try
        {
            var realm = ParseIdentity("ARCFORGES_INSTALLATION_CREDENTIAL_REALM");
            var installation = ParseIdentity("ARCFORGES_INSTALLATION_CREDENTIAL_INSTALLATION");
            var scope = new InstallationCredentialScope(new RealmId(realm), SecretApplicationDimension.ArcScope,
                InstallationCredentialPlatform.Windows, new InstallationId(installation));
            var opened = InstallationCredentialBroker.CreateForCurrentPlatform(scope, SecretIsolationPolicy.AllowSameUserSharedStore);
            if (!opened.TryGetValue(out var broker)) Environment.Exit(3);
            if (mode == "initialize")
            {
                try
                {
                    var result = broker.InitializeNewInstallationAsync().AsTask().GetAwaiter().GetResult();
                    if (!result.TryGetValue(out var identity)) Environment.Exit(4);
                    Console.WriteLine("KEY " + identity.KeyVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)
                        + " " + Convert.ToBase64String(identity.GetPublicKey()));
                }
                finally { broker.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
                Environment.Exit(0);
            }
            if (mode == "abandon")
            {
                using var mutex = new Mutex(false, "Global\\ArcForges.InstallationCredential.v1."
                    + broker.StorageTarget["ArcForges.Secrets.v1.".Length..]);
                mutex.WaitOne(); Console.WriteLine("HELD"); Console.Out.Flush();
                Thread.Sleep(Timeout.Infinite); // Parent kills only this owned process and confirms actual exit.
            }
            Environment.Exit(5);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        { Console.Error.WriteLine(exception.GetType().Name); Environment.Exit(1); }
    }

    private static Guid ParseIdentity(string variable)
    {
        var value = Environment.GetEnvironmentVariable(variable);
        if (!Guid.TryParseExact(value, "N", out var result) || result == Guid.Empty) throw new InvalidDataException("Owned child identity is invalid.");
        return result;
    }
}
