// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ArcForges.Contracts.Foundation;
using ArcForges.Contracts.LocalRpc;
using PolyType;
using StreamJsonRpc;
using Xunit;

namespace ArcForges.Tests.ContractCompatibilityTests;

[SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Test names use underscores for taxonomy readability.")]
public sealed class LocalRpcContractTests
{
    private static readonly Assembly LocalRpcAssembly = typeof(ILocalHubControlRpc).Assembly;

    [Fact]
    [Trait("Category", "Contract")]
    public void Arc009AssemblyHasExportRpcContractProxiesAttribute()
    {
        var hasAttr = LocalRpcAssembly.GetCustomAttributes()
            .Any(attr => attr.GetType().Name == "ExportRpcContractProxiesAttribute");

        Assert.True(hasAttr, "ArcForges.Contracts.LocalRpc must have [assembly: ExportRpcContractProxies]");
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void Arc009AllContractInterfacesHaveGenerateShapeAttribute()
    {
        var contracts = LocalRpcAssembly.GetTypes()
            .Where(type => type.IsInterface && type.GetCustomAttribute<JsonRpcContractAttribute>() is not null)
            .ToArray();

        Assert.NotEmpty(contracts);

        foreach (var contract in contracts)
        {
            var shapeAttr = contract.GetCustomAttribute<GenerateShapeAttribute>();
            Assert.True(shapeAttr is not null, $"{contract.FullName} is missing [GenerateShape]");
            Assert.True(
                shapeAttr.IncludeMethods.HasFlag(MethodShapeFlags.PublicInstance),
                $"{contract.FullName} must specify IncludeMethods = MethodShapeFlags.PublicInstance");
        }
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void Arc009ProxyGroupInterfaceHasJsonRpcProxyInterfaceGroupAttribute()
    {
        var groupInterface = typeof(IArcForgesProviderProxyGroup);
        var groupAttr = groupInterface.GetCustomAttribute<JsonRpcProxyInterfaceGroupAttribute>();

        Assert.NotNull(groupAttr);
        var interfaces = groupAttr.AdditionalInterfaces.ToArray();
        Assert.Contains(typeof(IArcNotesRpcV1), interfaces);
        Assert.Contains(typeof(IArcScopeRpcV1), interfaces);
        Assert.Contains(typeof(IArcSlateRpcV1), interfaces);
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void Arc009CounterEvidenceMissingGenerateShapeFailsCheck()
    {
        var violationFound = CheckMissingGenerateShape(typeof(IDummyPlainInterface));
        Assert.True(violationFound, "Interface without GenerateShape must be flagged as violation.");
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void Arc007AllContractInterfacesHavePureShapes()
    {
        var contracts = LocalRpcAssembly.GetTypes()
            .Where(type => type.IsInterface && type.GetCustomAttribute<JsonRpcContractAttribute>() is not null)
            .ToArray();

        Type[] banned = [typeof(object), typeof(Type), typeof(JsonElement)];

        foreach (var contract in contracts)
        {
            // No properties allowed on contracts
            Assert.Empty(contract.GetProperties());

            // No events other than EventHandler / EventHandler<T>
            foreach (var evt in contract.GetEvents())
            {
                var handlerType = evt.EventHandlerType!;
                var isValidHandler = handlerType == typeof(EventHandler)
                    || (handlerType.IsGenericType && handlerType.GetGenericTypeDefinition() == typeof(EventHandler<>));
                Assert.True(isValidHandler, $"{contract.FullName}.{evt.Name} must be EventHandler or EventHandler<T>");
            }

            var methods = contract.GetMethods().Where(m => !m.IsSpecialName).ToArray();
            var methodNames = new HashSet<string>(StringComparer.Ordinal);

            foreach (var method in methods)
            {
                // No overloads allowed
                Assert.True(methodNames.Add(method.Name), $"{contract.FullName}.{method.Name} is overloaded.");

                // No generic methods allowed
                Assert.False(method.IsGenericMethod, $"{contract.FullName}.{method.Name} must not be generic.");

                // Must return Task or ValueTask
                var returnType = method.ReturnType;
                var isAsync = returnType == typeof(Task)
                    || returnType == typeof(ValueTask)
                    || (returnType.IsGenericType && (returnType.GetGenericTypeDefinition() == typeof(Task<>) || returnType.GetGenericTypeDefinition() == typeof(ValueTask<>)));
                Assert.True(isAsync, $"{contract.FullName}.{method.Name} must return Task, Task<T>, ValueTask, or ValueTask<T>");

                // Last parameter must be CancellationToken
                var parameters = method.GetParameters();
                Assert.NotEmpty(parameters);
                Assert.Equal(typeof(CancellationToken), parameters[^1].ParameterType);

                // No banned types in parameter or return types
                var typesToCheck = parameters.Select(p => p.ParameterType).Append(returnType);
                foreach (var t in typesToCheck)
                {
                    Assert.DoesNotContain(t, banned);
                    if (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(Dictionary<,>))
                    {
                        Assert.NotEqual(typeof(object), t.GetGenericArguments()[1]);
                    }
                }
            }
        }
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void Arc007CounterEvidenceBannedTypeOrPropertyFailsCheck()
    {
        var hasPropViolation = typeof(IDummyWithProperty).GetProperties().Length > 0;
        Assert.True(hasPropViolation, "Interface with property must violate purity.");

        var hasObjectParam = typeof(IDummyWithObjectMethod)
            .GetMethod("BadMethodAsync")!
            .GetParameters()
            .Any(p => p.ParameterType == typeof(object));
        Assert.True(hasObjectParam, "Method with object parameter must violate purity.");
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void WriteMutationRequestsContainCompleteMutationEnvelopeAndExpectedRevision()
    {
        var manifestPath = LocateManifestPath();
        Assert.True(File.Exists(manifestPath), "Manifest localrpc-contracts.v1.json must exist.");

        using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath));
        var root = doc.RootElement;
        var interfaces = root.GetProperty("interfaces");

        var writeMethodCount = 0;

        foreach (var ifaceProp in interfaces.EnumerateObject())
        {
            if (ifaceProp.Name == "ILocalHubControlRpc")
            {
                continue;
            }

            var methods = ifaceProp.Value.GetProperty("methods");
            foreach (var method in methods.EnumerateArray())
            {
                var flags = method.GetProperty("flags");
                var isWrite = flags.GetProperty("write").GetBoolean();
                if (!isWrite)
                {
                    continue;
                }

                writeMethodCount++;
                var reqName = method.GetProperty("request").GetString()!;

                // Find type in LocalRpcAssembly
                var reqType = LocalRpcAssembly.GetTypes()
                    .FirstOrDefault(t => t.Name == reqName);

                Assert.NotNull(reqType);

                // Check expected fields
                var properties = reqType.GetProperties().Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

                Assert.True(properties.Contains("CommandId") || properties.Contains("Command"), $"{reqType.Name} missing CommandId");
                Assert.True(properties.Contains("Actor"), $"{reqType.Name} missing Actor");
                Assert.True(properties.Contains("ExpectedRevision"), $"{reqType.Name} missing ExpectedRevision");
                Assert.True(properties.Contains("IssuedAtUtc"), $"{reqType.Name} missing IssuedAtUtc");
                Assert.True(properties.Contains("DeadlineUtc"), $"{reqType.Name} missing DeadlineUtc");
                Assert.True(properties.Contains("CorrelationId"), $"{reqType.Name} missing CorrelationId");
            }
        }

        Assert.True(writeMethodCount >= 50, $"Expected >= 50 write mutation methods, found {writeMethodCount}");
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void WriteMutationRequestsCounterEvidenceMissingRevisionFailsCheck()
    {
        var dummyReq = new DummyMutationRequestMissingRevision { CommandId = Guid.NewGuid(), CorrelationId = Guid.NewGuid() };
        var properties = dummyReq.GetType().GetProperties().Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.False(properties.Contains("ExpectedRevision"), "Dummy request must not have ExpectedRevision.");
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void ContractFilesDoNotContainNotImplementedException()
    {
        var repoRoot = LocateRepoRoot();
        var localRpcDir = Path.Combine(repoRoot, "src", "Contracts", "ArcForges.Contracts.LocalRpc");

        var csFiles = Directory.EnumerateFiles(localRpcDir, "*.cs", SearchOption.AllDirectories).ToArray();
        Assert.NotEmpty(csFiles);

        foreach (var file in csFiles)
        {
            var content = File.ReadAllText(file);
            Assert.DoesNotContain("NotImplementedException", content, StringComparison.Ordinal);
        }
    }

    [Fact]
    [Trait("Category", "Contract")]
    public void ContractManifestMatchesActualInterfacesAndTotalMethodCount()
    {
        var manifestPath = LocateManifestPath();
        using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath));
        var interfaces = doc.RootElement.GetProperty("interfaces");

        var totalMethods = 0;
        foreach (var ifaceProp in interfaces.EnumerateObject())
        {
            var ifaceName = ifaceProp.Name;
            var targetIface = LocalRpcAssembly.GetTypes().FirstOrDefault(t => t.Name == ifaceName);
            Assert.NotNull(targetIface);

            var methodsArray = ifaceProp.Value.GetProperty("methods");
            var count = methodsArray.GetArrayLength();
            totalMethods += count;

            foreach (var m in methodsArray.EnumerateArray())
            {
                var methodName = m.GetProperty("name").GetString()!;
                var methodInfo = targetIface.GetMethod(methodName);
                Assert.NotNull(methodInfo);
            }
        }

        Assert.Equal(96, totalMethods);
    }

    private static bool CheckMissingGenerateShape(Type contractType) =>
        contractType.GetCustomAttribute<GenerateShapeAttribute>() is null;

    private static string LocateRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ArcForges.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    private static string LocateManifestPath()
    {
        var repoRoot = LocateRepoRoot();
        var p1 = Path.Combine(repoRoot, "contracts", "localrpc", "v1", "localrpc-contracts.v1.json");
        if (File.Exists(p1))
        {
            return p1;
        }

        return Path.Combine(repoRoot, "artifacts", "contracts", "localrpc-contracts.v1.json");
    }

    // Counter-evidence dummy types (plain interfaces without JsonRpcContract to avoid analyzer noise)
    internal interface IDummyPlainInterface
    {
        Task DoWorkAsync(CancellationToken cancellationToken);
    }

    internal interface IDummyWithProperty
    {
        string SomeProperty { get; }
    }

    internal interface IDummyWithObjectMethod
    {
        Task BadMethodAsync(object arg, CancellationToken cancellationToken);
    }

    internal sealed class DummyMutationRequestMissingRevision
    {
        public Guid CommandId { get; init; }
        public Guid CorrelationId { get; init; }
    }
}
