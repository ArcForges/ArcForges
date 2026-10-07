// SPDX-License-Identifier: AGPL-3.0-only

using System.Security.Cryptography;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace ArcForges.Build.Policy.Architecture;

/// <summary>Source-bound, closed immutable metadata classification; never a namespace or wire exemption.</summary>
internal static class NonWireMetadataPolicy
{
    private const int TraversalLimit = 2048;
    private static readonly HashSet<string> Strings = new(StringComparer.Ordinal)
    {
        "OperationId", "Binding", "Surface", "Scope", "Idempotency", "Profile", "SourceRule", "Capability",
        "Risk", "RiskSource", "Approval", "StepUpSource", "LocalPresenceSource", "Egress",
    };

    public static HashSet<INamedTypeSymbol> Check(RepositoryFacts repository, RepositoryPolicyConfiguration configuration,
        IReadOnlyDictionary<INamedTypeSymbol, ProjectFacts> projects,
        IReadOnlyDictionary<string, Microsoft.CodeAnalysis.CSharp.CSharpCompilation> compilations,
        List<PolicyFinding> findings)
    {
        var accepted = new HashSet<INamedTypeSymbol>(SymbolEqualityComparer.Default);
        var bindings = configuration.NonWireMetadataBindings;
        if (bindings is null || bindings.Count == 0) return accepted;
        var candidates = new List<(NonWireMetadataBinding Binding, INamedTypeSymbol Type, ProjectFacts Project)>();
        foreach (var binding in bindings)
        {
            var matches = projects.Where(pair => pair.Key.ToDisplayString() == binding.TypeSymbol).ToArray();
            if (bindings.Count(other => other.TypeSymbol == binding.TypeSymbol) != 1 || matches.Length != 1
                || configuration.WireTypes.Any(wire => wire.TypeSymbol == binding.TypeSymbol)
                || !Identity(repository, binding, matches[0].Key, matches[0].Value))
            {
                Refuse(binding.ProjectPath, "Missing, duplicate, ambiguous or invalid reviewed metadata source binding: " + binding.TypeSymbol);
                continue;
            }

            candidates.Add((binding, matches[0].Key, matches[0].Value));
        }

        foreach (var entry in candidates.Where(entry => entry.Binding.Kind == NonWireMetadataKind.OperationAuthorizationPolicy))
        {
            var compilation = compilations[entry.Project.Classification.Path];
            if (PolicyShape(entry.Type, compilation)) accepted.Add(entry.Type);
            else Refuse(entry.Binding.ProjectPath, "Metadata is not the closed immutable authorization policy: " + entry.Type);
        }

        foreach (var entry in candidates.Where(entry => entry.Binding.Kind == NonWireMetadataKind.OperationAuthorizationCatalog))
        {
            var compilation = compilations[entry.Project.Classification.Path];
            if (CatalogShape(entry.Type, compilation, accepted)) accepted.Add(entry.Type);
            else Refuse(entry.Binding.ProjectPath, "Metadata is not a canonical immutable authorization catalog: " + entry.Type);
        }

        var flow = new Flow(projects, compilations, accepted);
        foreach (var pair in projects.Where(pair => pair.Value.Classification.Production && !accepted.Contains(pair.Key)))
        {
            var type = pair.Key;
            var role = pair.Value.Classification.Role;
            bool payload = role == ProjectRole.Contracts && type.DeclaredAccessibility == Accessibility.Public
                && flow.Reaches(type, new HashSet<string>(StringComparer.Ordinal));
            bool rpc = role is ProjectRole.LocalRpcAdapter or ProjectRole.PublicApiAdapter
                && type.GetMembers().OfType<IMethodSymbol>().Any(method => method.DeclaredAccessibility == Accessibility.Public
                    && method.MethodKind == MethodKind.Ordinary && method.Parameters.Select(parameter => parameter.Type)
                        .Append(method.ReturnType).Any(argument => flow.Reaches(argument, new HashSet<string>(StringComparer.Ordinal))));
            bool registration = type.GetAttributes().Any(attribute => SerializerAttribute(attribute)
                && attribute.ConstructorArguments.Concat(attribute.NamedArguments.Select(argument => argument.Value)).Any(flow.AttributeReaches));
            if (payload || rpc || registration || flow.Exhausted)
                Refuse(pair.Value.Classification.Path, "Reviewed non-wire metadata reaches a wire/RPC/serializer payload: " + type);
            flow.Reset();
        }

        foreach (var project in projects.Values.Distinct().Where(project => project.Classification.Production
            && project.Classification.Role != ProjectRole.BuildTool))
        {
            var compilation = compilations[project.Classification.Path];
            foreach (var tree in compilation.SyntaxTrees)
            {
                var model = compilation.GetSemanticModel(tree);
                foreach (var invocation in tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    if (model.GetSymbolInfo(invocation).Symbol is not IMethodSymbol method || !flow.Sink(method)) continue;
                    bool escape = invocation.ArgumentList.Arguments.Any(argument => flow.Expression(argument.Expression, model,
                        new HashSet<ISymbol>(SymbolEqualityComparer.Default)));
                    if (escape || flow.Exhausted)
                        Refuse(project.Classification.Path, "Reviewed non-wire metadata escapes through a serialization/transport invocation: " + method);
                    flow.Reset();
                }
            }
        }

        return accepted;
        void Refuse(string path, string message) => findings.Add(new PolicyFinding("AT-12", path, message));
    }

    private static bool Identity(RepositoryFacts repository, NonWireMetadataBinding binding, INamedTypeSymbol type, ProjectFacts project)
    {
        if (binding.Kind is not (NonWireMetadataKind.OperationAuthorizationPolicy or NonWireMetadataKind.OperationAuthorizationCatalog)
            || project.Classification.Path != binding.ProjectPath || project.Classification.Owner != repository.Owner
            || project.Classification.Role != ProjectRole.Contracts || !project.Classification.Production
            || type.TypeKind != TypeKind.Class || type.Arity != 0 || type.ContainingType is not null
            || type.DeclaredAccessibility != Accessibility.Public || type.DeclaringSyntaxReferences.Length != 1
            || binding.SourceSha256.Length != 64 || binding.SourceSha256.Any(character => !char.IsAsciiHexDigit(character) || char.IsUpper(character))
            || !Relative(binding.SourcePath) || !Relative(binding.ProjectPath)) return false;
        try
        {
            string source = ProjectGraph.ContainedPath(repository.Root, binding.SourcePath);
            string projectDirectory = Path.GetDirectoryName(ProjectGraph.ContainedPath(repository.Root, binding.ProjectPath))!;
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (!source.StartsWith(projectDirectory + Path.DirectorySeparatorChar, comparison)
                || !File.Exists(source) || new FileInfo(source).Length > 4 * 1024 * 1024
                || !project.Sources.Any(path => string.Equals(Path.GetFullPath(Path.IsPathRooted(path) ? path : Path.Combine(repository.Root, path)), source, comparison))) return false;
            for (string? path = source; path is not null && !string.Equals(path, Path.GetFullPath(repository.Root), comparison); path = Path.GetDirectoryName(path))
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return false;
            var declaration = type.DeclaringSyntaxReferences[0].GetSyntax();
            if (declaration is not ClassDeclarationSyntax syntax || syntax.Modifiers.Any(modifier => modifier.ValueText == "partial")) return false;
            string treePath = declaration.SyntaxTree.FilePath;
            string compiledPath = Path.GetFullPath(Path.IsPathRooted(treePath) ? treePath : Path.Combine(repository.Root, treePath));
            if (!string.Equals(compiledPath, source, comparison)) return false;
            string disk = new UTF8Encoding(false, true).GetString(File.ReadAllBytes(source));
            return Hash(disk) == binding.SourceSha256 && Hash(declaration.SyntaxTree.GetText().ToString()) == binding.SourceSha256;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool Relative(string path) => path.Length > 0 && !Path.IsPathRooted(path) && !path.Contains('\\', StringComparison.Ordinal)
        && path.Split('/').All(part => part.Length > 0 && part is not "." and not "..");

    private static string Hash(string text)
    {
        if (text.StartsWith('\uFEFF')) text = text[1..];
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text.Replace("\r\n", "\n", StringComparison.Ordinal))));
    }

    private static bool Plain(INamedTypeSymbol type) => type.BaseType?.SpecialType == SpecialType.System_Object
        && type.Interfaces.Length == 0 && !type.GetAttributes().Any(SerializerAttribute)
        && !type.GetMembers().Any(member => member is IEventSymbol or INamedTypeSymbol
            || member.GetAttributes().Any(SerializerAttribute));

    private static bool PolicyShape(INamedTypeSymbol type, Microsoft.CodeAnalysis.CSharp.CSharpCompilation compilation)
    {
        if (!type.IsSealed || type.IsStatic || !Plain(type)
            || type.GetMembers().OfType<IFieldSymbol>().Any(field => !field.IsImplicitlyDeclared || !field.IsReadOnly)
            || type.GetMembers().OfType<IMethodSymbol>().Any(method => method.MethodKind == MethodKind.Ordinary && method.DeclaredAccessibility == Accessibility.Public)) return false;
        var properties = type.GetMembers().OfType<IPropertySymbol>().ToArray();
        if (properties.Length != 19 || properties.Any(property => property.DeclaredAccessibility != Accessibility.Public || property.IsStatic
            || property.SetMethod is not null || property.IsIndexer || property.GetMethod is null)) return false;
        foreach (var property in properties)
        {
            if (Strings.Contains(property.Name))
            {
                if (property.Type.SpecialType != SpecialType.System_String) return false;
            }
            else if (property.Name == "PatEligible")
            {
                if (property.Type.SpecialType != SpecialType.System_Boolean) return false;
            }
            else if (property.Name is "StepUp" or "LocalPresence")
            {
                if (property.Type is not INamedTypeSymbol nullable || nullable.OriginalDefinition.SpecialType != SpecialType.System_Nullable_T
                    || nullable.TypeArguments[0].SpecialType != SpecialType.System_Boolean) return false;
            }
            else if (property.Name is "PatScopes" or "ActorKinds")
            {
                if (!List(property.Type, out var element) || element.SpecialType != SpecialType.System_String
                    || !ReadOnlyAssignments(property, compilation)) return false;
            }
            else return false;
            if (property.Name == "Surface")
            {
                var syntax = property.DeclaringSyntaxReferences.Single().GetSyntax() as PropertyDeclarationSyntax;
                if (syntax?.ExpressionBody is null || compilation.GetSemanticModel(syntax.SyntaxTree).GetConstantValue(syntax.ExpressionBody.Expression).Value is not "public") return false;
            }
            else if (property.DeclaringSyntaxReferences.Single().GetSyntax() is not PropertyDeclarationSyntax { AccessorList: { } accessors }
                || accessors.Accessors.Any(accessor => accessor.Body is not null || accessor.ExpressionBody is not null)) return false;
        }

        return Strings.All(name => properties.Any(property => property.Name == name));
    }

    private static bool CatalogShape(INamedTypeSymbol type, Microsoft.CodeAnalysis.CSharp.CSharpCompilation compilation, HashSet<INamedTypeSymbol> policies)
    {
        if (!type.IsStatic || !Plain(type) || type.StaticConstructors.Any(constructor => !constructor.IsImplicitlyDeclared)) return false;
        var properties = type.GetMembers().OfType<IPropertySymbol>().ToArray();
        var methods = type.GetMembers().OfType<IMethodSymbol>().Where(method => method.MethodKind == MethodKind.Ordinary).ToArray();
        var fields = type.GetMembers().OfType<IFieldSymbol>().Where(field => !field.IsImplicitlyDeclared).ToArray();
        if (properties.Length != 1 || properties[0].Name != "All" || !properties[0].IsStatic || properties[0].SetMethod is not null
            || properties[0].DeclaredAccessibility != Accessibility.Public || !List(properties[0].Type, out var policy)
            || !policies.Any(accepted => Same(accepted, policy)) || !ReadOnlyAssignments(properties[0], compilation)
            || methods.Length != 1 || methods[0].Name != "TryGet" || !methods[0].IsStatic || methods[0].Arity != 0
            || methods[0].DeclaredAccessibility != Accessibility.Public || methods[0].ReturnType.SpecialType != SpecialType.System_Boolean
            || methods[0].Parameters.Length != 2 || methods[0].Parameters[0].Type.SpecialType != SpecialType.System_String
            || methods[0].Parameters[1].RefKind != RefKind.Out || !Same(methods[0].Parameters[1].Type, policy)
            || fields.Length != 1 || !fields[0].IsStatic || !fields[0].IsReadOnly || fields[0].DeclaredAccessibility != Accessibility.Private
            || fields[0].Type is not INamedTypeSymbol dictionary || dictionary.OriginalDefinition.ToDisplayString() != "System.Collections.Frozen.FrozenDictionary<TKey, TValue>"
            || dictionary.TypeArguments[0].SpecialType != SpecialType.System_String || !Same(dictionary.TypeArguments[1], policy)) return false;
        var field = (VariableDeclaratorSyntax)fields[0].DeclaringSyntaxReferences.Single().GetSyntax();
        var model = compilation.GetSemanticModel(field.SyntaxTree);
        if (field.Initializer?.Value is not InvocationExpressionSyntax { Expression: MemberAccessExpressionSyntax member } factory
            || !Canonical(model, factory, "System.Collections.Frozen.FrozenDictionary", "ToFrozenDictionary")
            || !SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(member.Expression).Symbol, properties[0]) || factory.ArgumentList.Arguments.Count != 2
            || factory.ArgumentList.Arguments[0].Expression is not SimpleLambdaExpressionSyntax { ExpressionBody: MemberAccessExpressionSyntax key }
            || model.GetSymbolInfo(key).Symbol is not IPropertySymbol { Name: "OperationId", Type.SpecialType: SpecialType.System_String } keyProperty
            || !Same(keyProperty.ContainingType, policy)
            || model.GetSymbolInfo(factory.ArgumentList.Arguments[1].Expression).Symbol is not IPropertySymbol ordinal
            || ordinal.Name != "Ordinal" || ordinal.ContainingType.ToDisplayString() != "System.StringComparer"
            || ordinal.DeclaringSyntaxReferences.Length != 0 || !Core(ordinal.ContainingAssembly)) return false;
        var methodSyntax = (MethodDeclarationSyntax)methods[0].DeclaringSyntaxReferences.Single().GetSyntax();
        model = compilation.GetSemanticModel(methodSyntax.SyntaxTree);
        if (methodSyntax.Body is null || methodSyntax.Body.Statements.LastOrDefault() is not ReturnStatementSyntax { Expression: InvocationExpressionSyntax lookup }
            || lookup.Expression is not MemberAccessExpressionSyntax receiver || model.GetSymbolInfo(receiver.Expression).Symbol is not IFieldSymbol stored
            || !SymbolEqualityComparer.Default.Equals(stored, fields[0]) || model.GetSymbolInfo(lookup).Symbol is not IMethodSymbol { Name: "TryGetValue" } called
            || !Core(called.ContainingAssembly)
            || !SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(lookup.ArgumentList.Arguments[0].Expression).Symbol, methods[0].Parameters[0])
            || !SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(lookup.ArgumentList.Arguments[1].Expression).Symbol, methods[0].Parameters[1])) return false;
        return methodSyntax.Body.Statements.SkipLast(1).All(statement => statement is ExpressionStatementSyntax { Expression: InvocationExpressionSyntax guard }
            && Canonical(model, guard, "System.ArgumentNullException", "ThrowIfNull")
            && SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(guard.ArgumentList.Arguments[0].Expression).Symbol, methods[0].Parameters[0]));
    }

    private static bool List(ITypeSymbol type, out ITypeSymbol element)
    {
        if (type is INamedTypeSymbol named && named.OriginalDefinition.ToDisplayString() == "System.Collections.Generic.IReadOnlyList<T>"
            && named.DeclaringSyntaxReferences.Length == 0 && Core(named.ContainingAssembly))
        {
            element = named.TypeArguments[0]; return true;
        }
        element = type; return false;
    }

    private static bool ReadOnlyAssignments(IPropertySymbol property, Microsoft.CodeAnalysis.CSharp.CSharpCompilation compilation)
    {
        var syntax = (PropertyDeclarationSyntax)property.DeclaringSyntaxReferences.Single().GetSyntax();
        var model = compilation.GetSemanticModel(syntax.SyntaxTree);
        var assignments = syntax.Parent!.DescendantNodes().OfType<AssignmentExpressionSyntax>()
            .Where(assignment => SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(assignment.Left).Symbol, property)).Select(assignment => assignment.Right).ToList();
        if (syntax.Initializer is not null) assignments.Add(syntax.Initializer.Value);
        return assignments.Count > 0 && assignments.All(expression => expression is InvocationExpressionSyntax invocation
            && Canonical(model, invocation, "System.Array", "AsReadOnly") && invocation.ArgumentList.Arguments.Count == 1
            && Fresh(invocation.ArgumentList.Arguments[0].Expression, model, new HashSet<ISymbol>(SymbolEqualityComparer.Default)));
    }

    private static bool Fresh(ExpressionSyntax expression, SemanticModel model, HashSet<ISymbol> visited)
    {
        if (expression is ParenthesizedExpressionSyntax parentheses) return Fresh(parentheses.Expression, model, visited);
        if (expression is CastExpressionSyntax cast) return Fresh(cast.Expression, model, visited);
        if (expression is ArrayCreationExpressionSyntax or ImplicitArrayCreationExpressionSyntax or CollectionExpressionSyntax) return true;
        if (expression is ConditionalExpressionSyntax conditional) return Fresh(conditional.WhenTrue, model, visited) && Fresh(conditional.WhenFalse, model, visited);
        if (expression is InvocationExpressionSyntax invocation) return Canonical(model, invocation, "System.Array", "Empty")
            || Canonical(model, invocation, "System.Linq.Enumerable", "ToArray");
        if (model.GetSymbolInfo(expression).Symbol is not ILocalSymbol local || !visited.Add(local)
            || local.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() is not VariableDeclaratorSyntax { Initializer: { } initializer } declaration
            || !Fresh(initializer.Value, model, visited)) return false;
        foreach (var use in declaration.SyntaxTree.GetRoot().DescendantNodes().OfType<IdentifierNameSyntax>()
            .Where(name => SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(name).Symbol, local)))
        {
            if (use.Ancestors().OfType<AssignmentExpressionSyntax>().Any(assignment => assignment.Left.Span.Contains(use.Span))) return false;
            if (use.Ancestors().OfType<AssignmentExpressionSyntax>().Any(assignment => assignment.Right.Span.Contains(use.Span)
                && model.GetTypeInfo(assignment.Right).Type is { IsReferenceType: true, SpecialType: not SpecialType.System_String }
                && (assignment.Right is not InvocationExpressionSyntax readonlyCall || !Canonical(model, readonlyCall, "System.Array", "AsReadOnly")))) return false;
            if (use.Ancestors().OfType<EqualsValueClauseSyntax>().Any(value => !SafeSnapshotResult(value.Value, model))) return false;
            if (use.Ancestors().OfType<ReturnStatementSyntax>().Any(returned => returned.Expression is { } value && !SafeSnapshotResult(value, model))
                || use.Ancestors().OfType<YieldStatementSyntax>().Any(returned => returned.Expression is { } value && !SafeSnapshotResult(value, model))
                || use.Ancestors().OfType<ArrowExpressionClauseSyntax>().Any(arrow => !SafeSnapshotResult(arrow.Expression, model))) return false;
            foreach (var argument in use.Ancestors().OfType<ArgumentSyntax>())
            {
                if (SafeSnapshotResult(argument.Expression, model)) continue;
                ExpressionSyntax input = argument.Expression;
                while (input is ParenthesizedExpressionSyntax or CastExpressionSyntax)
                    input = input is ParenthesizedExpressionSyntax parenthesized ? parenthesized.Expression : ((CastExpressionSyntax)input).Expression;
                if (input != use || argument.Parent?.Parent is not InvocationExpressionSyntax call
                    || !Canonical(model, call, "System.Array", "AsReadOnly") && !Canonical(model, call, "System.Linq.Enumerable", "ToArray")) return false;
            }
        }
        return true;
    }

    private static bool SafeSnapshotResult(ExpressionSyntax expression, SemanticModel model)
    {
        while (expression is ParenthesizedExpressionSyntax or CastExpressionSyntax)
            expression = expression is ParenthesizedExpressionSyntax parentheses ? parentheses.Expression : ((CastExpressionSyntax)expression).Expression;
        return Primitive(model.GetTypeInfo(expression).Type)
            || expression is InvocationExpressionSyntax invocation && (Canonical(model, invocation, "System.Array", "AsReadOnly")
                || Canonical(model, invocation, "System.Linq.Enumerable", "ToArray"));
    }

    private static bool Primitive(ITypeSymbol? type) => type?.SpecialType is SpecialType.System_String or SpecialType.System_Boolean
        or SpecialType.System_Char or SpecialType.System_Byte or SpecialType.System_SByte or SpecialType.System_Int16
        or SpecialType.System_UInt16 or SpecialType.System_Int32 or SpecialType.System_UInt32 or SpecialType.System_Int64
        or SpecialType.System_UInt64 or SpecialType.System_Single or SpecialType.System_Double or SpecialType.System_Decimal
        || type is INamedTypeSymbol named && named.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T
            && named.DeclaringSyntaxReferences.Length == 0 && Core(named.ContainingAssembly) && Primitive(named.TypeArguments[0]);

    private static bool Canonical(SemanticModel model, InvocationExpressionSyntax invocation, string type, string name) =>
        model.GetSymbolInfo(invocation).Symbol is IMethodSymbol method && method.Name == name
        && method.ContainingType.ToDisplayString() == type && method.DeclaringSyntaxReferences.Length == 0 && Core(method.ContainingAssembly);
    private static bool Core(IAssemblySymbol assembly) => (assembly.Name == "System.Private.CoreLib" || assembly.Name.StartsWith("System.", StringComparison.Ordinal))
        && assembly.DeclaringSyntaxReferences.Length == 0
        && Convert.ToHexStringLower(assembly.Identity.PublicKeyToken.AsSpan()) is "7cec85d7bea7798e" or "b03f5f7f11d50a3a" or "cc7b13ffcd2ddd51";
    private static bool Same(ITypeSymbol first, ITypeSymbol second) => first.ToDisplayString().TrimEnd('?') == second.ToDisplayString().TrimEnd('?')
        && first.ContainingAssembly?.Identity.Equals(second.ContainingAssembly?.Identity) == true;
    private static bool SerializerAttribute(AttributeData attribute)
    {
        string name = attribute.AttributeClass?.ToDisplayString() ?? "";
        var assembly = attribute.AttributeClass?.ContainingAssembly;
        if (assembly is null) return false;
        return attribute.AttributeClass!.DeclaringSyntaxReferences.Length == 0 && Core(assembly) && (name.StartsWith("System.Text.Json.Serialization.", StringComparison.Ordinal)
            || name.StartsWith("System.Runtime.Serialization.", StringComparison.Ordinal) || name.StartsWith("System.Xml.Serialization.", StringComparison.Ordinal))
            || attribute.AttributeClass!.DeclaringSyntaxReferences.Length == 0 && (assembly.Name == "Newtonsoft.Json" && name.StartsWith("Newtonsoft.Json.", StringComparison.Ordinal)
                || assembly.Name == "protobuf-net" && name.StartsWith("ProtoBuf.", StringComparison.Ordinal));
    }

    /// <summary>Immutable owner buckets; candidate order and the authoritative Same comparison are retained.</summary>
    internal sealed class OwnerIndex
    {
        private readonly System.Collections.Frozen.FrozenDictionary<string, KeyValuePair<INamedTypeSymbol, ProjectFacts>[]> _owners;

        public OwnerIndex(IReadOnlyDictionary<INamedTypeSymbol, ProjectFacts> projects)
        {
            _owners = System.Collections.Frozen.FrozenDictionary.ToFrozenDictionary(
                projects.GroupBy(pair => Key(pair.Key), StringComparer.Ordinal),
                group => group.Key, group => group.ToArray(), StringComparer.Ordinal);
        }

        private static string Key(ITypeSymbol type) => type.ToDisplayString().TrimEnd('?');
        public INamedTypeSymbol? First(ITypeSymbol type) => _owners.TryGetValue(Key(type), out var candidates)
            ? candidates.FirstOrDefault(pair => Same(pair.Key, type)).Key : null;
        public bool HasAdapter(ITypeSymbol type) => _owners.TryGetValue(Key(type), out var candidates)
            && candidates.Any(pair => Same(pair.Key, type)
                && pair.Value.Classification.Role is ProjectRole.PublicApiAdapter or ProjectRole.LocalRpcAdapter);
    }

    private sealed class Flow
    {
        private readonly OwnerIndex _owners;
        private readonly HashSet<INamedTypeSymbol> _metadata;
        private readonly Dictionary<ISymbol, List<(ExpressionSyntax Expression, SemanticModel Model)>> _sources = new(SymbolEqualityComparer.Default);
        private int _steps;
        public bool Exhausted { get; private set; }
        public Flow(IReadOnlyDictionary<INamedTypeSymbol, ProjectFacts> projects,
            IReadOnlyDictionary<string, Microsoft.CodeAnalysis.CSharp.CSharpCompilation> compilations, HashSet<INamedTypeSymbol> metadata)
        {
            _owners = new OwnerIndex(projects); _metadata = metadata;
            foreach (var compilation in compilations.Values)
                foreach (var tree in compilation.SyntaxTrees)
                {
                    var model = compilation.GetSemanticModel(tree);
                    foreach (var node in tree.GetRoot().DescendantNodes())
                    {
                        if (node is VariableDeclaratorSyntax { Initializer: { } initializer } variable) Add(model.GetDeclaredSymbol(variable), initializer.Value, model);
                        else if (node is PropertyDeclarationSyntax { Initializer: { } propertyInitializer } property) Add(model.GetDeclaredSymbol(property), propertyInitializer.Value, model);
                        else if (node is AssignmentExpressionSyntax assignment) Add(model.GetSymbolInfo(assignment.Left).Symbol, assignment.Right, model);
                        else if (node is ForEachStatementSyntax loop) Add(model.GetDeclaredSymbol(loop), loop.Expression, model);
                        else if (node is ReturnStatementSyntax { Expression: { } value } returned)
                            Add(ReturnOwner(returned, model), value, model);
                        else if (node is YieldStatementSyntax { Expression: { } yielded } iterator)
                            Add(ReturnOwner(iterator, model), yielded, model);
                        else if (node is ArrowExpressionClauseSyntax arrow) Add(model.GetDeclaredSymbol(arrow.Parent!), arrow.Expression, model);
                        else if (node is BaseObjectCreationExpressionSyntax creation && model.GetSymbolInfo(creation).Symbol is IMethodSymbol constructor
                            && constructor.DeclaringSyntaxReferences.Length != 0 && creation.ArgumentList is { } constructorArguments)
                            foreach (var argument in constructorArguments.Arguments)
                            {
                                int position = argument.NameColon is null ? constructorArguments.Arguments.IndexOf(argument)
                                    : Array.FindIndex(constructor.Parameters.ToArray(), parameter => parameter.Name == argument.NameColon.Name.Identifier.ValueText);
                                if (position >= 0 && position < constructor.Parameters.Length) Add(constructor.Parameters[position].OriginalDefinition, argument.Expression, model);
                            }
                        else if (node is InvocationExpressionSyntax invocation && model.GetSymbolInfo(invocation).Symbol is IMethodSymbol method
                            && method.DeclaringSyntaxReferences.Length != 0)
                            foreach (var argument in invocation.ArgumentList.Arguments)
                            {
                                int position = argument.NameColon is null ? invocation.ArgumentList.Arguments.IndexOf(argument)
                                    : Array.FindIndex(method.Parameters.ToArray(), parameter => parameter.Name == argument.NameColon.Name.Identifier.ValueText);
                                if (position >= 0 && position < method.Parameters.Length) Add(method.Parameters[position].OriginalDefinition, argument.Expression, model);
                            }
                        if (node is InvocationExpressionSyntax projection && Canonical(model, projection, "System.Linq.Enumerable", "Select")
                            && model.GetSymbolInfo(projection).Symbol is IMethodSymbol select)
                        {
                            var selector = projection.ArgumentList.Arguments.LastOrDefault()?.Expression;
                            var source = select.ReducedFrom is not null && projection.Expression is MemberAccessExpressionSyntax receiver
                                ? receiver.Expression : projection.ArgumentList.Arguments.FirstOrDefault()?.Expression;
                            var parameter = selector switch
                            {
                                SimpleLambdaExpressionSyntax simple => model.GetDeclaredSymbol(simple.Parameter),
                                ParenthesizedLambdaExpressionSyntax parenthesized => parenthesized.ParameterList.Parameters.FirstOrDefault() is { } first ? model.GetDeclaredSymbol(first) : null,
                                AnonymousMethodExpressionSyntax anonymous => anonymous.ParameterList?.Parameters.FirstOrDefault() is { } first ? model.GetDeclaredSymbol(first) : null,
                                _ => model.GetSymbolInfo(selector!).Symbol is IMethodSymbol selected ? selected.Parameters.FirstOrDefault() : null,
                            };
                            if (source is not null) Add(parameter, source, model);
                        }
                    }
                }
        }

        public void Reset() { _steps = 0; Exhausted = false; }
        private bool Step() { if (++_steps <= TraversalLimit) return true; Exhausted = true; return false; }
        private void Add(ISymbol? symbol, ExpressionSyntax expression, SemanticModel model)
        {
            if (symbol is null) return;
            symbol = symbol.OriginalDefinition;
            if (!_sources.TryGetValue(symbol, out var values)) _sources.Add(symbol, values = []);
            values.Add((expression, model));
        }
        private static ISymbol? ReturnOwner(SyntaxNode node, SemanticModel model)
        {
            var declaration = node.Ancestors().FirstOrDefault(parent => parent is MethodDeclarationSyntax or LocalFunctionStatementSyntax or AccessorDeclarationSyntax);
            return declaration is null ? null : model.GetDeclaredSymbol(declaration);
        }

        public bool Reaches(ITypeSymbol type, HashSet<string> visited)
        {
            if (!Step()) return false;
            if (_metadata.Any(metadata => Same(metadata, type))) return true;
            if (type is IArrayTypeSymbol array) return Reaches(array.ElementType, visited);
            if (type is not INamedTypeSymbol named) return false;
            string identity = named.ToDisplayString() + "|" + named.ContainingAssembly.Identity;
            if (!visited.Add(identity)) return false;
            if (named.TypeArguments.Any(argument => Reaches(argument, visited))) return true;
            var owned = _owners.First(named);
            if (owned is null || _metadata.Contains(owned)) return false;
            foreach (var member in owned.GetMembers())
            {
                var types = member switch
                {
                    IFieldSymbol field => new[] { field.Type },
                    IPropertySymbol property => [property.Type],
                    IMethodSymbol method => method.Parameters.Select(parameter => parameter.Type).Append(method.ReturnType),
                    IEventSymbol eventSymbol => [eventSymbol.Type],
                    _ => Enumerable.Empty<ITypeSymbol>(),
                };
                if (types.Any(argument => Reaches(argument, visited))) return true;
                if (member is IFieldSymbol or IPropertySymbol && Symbol(member, new HashSet<ISymbol>(SymbolEqualityComparer.Default))) return true;
            }
            return false;
        }

        public bool AttributeReaches(TypedConstant argument) => argument.Kind == TypedConstantKind.Type && argument.Value is ITypeSymbol type
            ? Reaches(type, new HashSet<string>(StringComparer.Ordinal))
            : argument.Kind == TypedConstantKind.Array && argument.Values.Any(AttributeReaches);

        public bool Sink(IMethodSymbol method)
        {
            string type = method.ContainingType.ToDisplayString();
            if (method.DeclaringSyntaxReferences.Length == 0 && Core(method.ContainingAssembly) && (type == "System.Text.Json.JsonSerializer" && method.Name.StartsWith("Serialize", StringComparison.Ordinal)
                || type == "System.Net.Http.Json.HttpClientJsonExtensions" && method.Name.Contains("AsJson", StringComparison.Ordinal)
                || type == "System.Xml.Serialization.XmlSerializer" && method.Name == "Serialize"
                || type is "System.Runtime.Serialization.XmlObjectSerializer" or "System.Runtime.Serialization.DataContractSerializer"
                    or "System.Runtime.Serialization.Json.DataContractJsonSerializer" && method.Name is "WriteObject" or "WriteObjectContent")) return true;
            if (method.DeclaringSyntaxReferences.Length == 0 && (method.ContainingAssembly.Name == "Newtonsoft.Json" && type == "Newtonsoft.Json.JsonConvert" && method.Name == "SerializeObject"
                || method.ContainingAssembly.Name == "protobuf-net" && type == "ProtoBuf.Serializer" && method.Name.StartsWith("Serialize", StringComparison.Ordinal))) return true;
            if (method.DeclaredAccessibility != Accessibility.Public) return false;
            return _owners.HasAdapter(method.ContainingType);
        }

        private bool Symbol(ISymbol symbol, HashSet<ISymbol> visited)
        {
            symbol = symbol.OriginalDefinition;
            if (visited.Count >= 128) { Exhausted = true; return false; }
            if (!Step() || !visited.Add(symbol)) return false;
            try
            {
                return symbol is IPropertySymbol { GetMethod: { } getter } && Symbol(getter, visited)
                    || _sources.TryGetValue(symbol, out var values) && values.Any(value => Expression(value.Expression, value.Model, visited));
            }
            finally { _ = visited.Remove(symbol); }
        }

        public bool Expression(ExpressionSyntax expression, SemanticModel model, HashSet<ISymbol> visited)
        {
            if (!Step()) return false;
            var type = model.GetTypeInfo(expression).Type;
            if (Primitive(type)) return false;
            if (model.GetSymbolInfo(expression).Symbol is IPropertySymbol { Name: "ActorKinds" or "PatScopes" } strings
                && _metadata.Any(metadata => Same(metadata, strings.ContainingType)) && List(strings.Type, out var element)
                && element.SpecialType == SpecialType.System_String) return false;
            if (type is not null && Reaches(type, new HashSet<string>(StringComparer.Ordinal))) return true;
            if (expression is CastExpressionSyntax cast) return Expression(cast.Expression, model, visited);
            if (expression is ParenthesizedExpressionSyntax parentheses) return Expression(parentheses.Expression, model, visited);
            if (expression is TupleExpressionSyntax tuple) return tuple.Arguments.Any(argument => Expression(argument.Expression, model, visited));
            if (expression is CollectionExpressionSyntax collection)
                return collection.Elements.Any(element => element switch
                {
                    ExpressionElementSyntax value => Expression(value.Expression, model, visited),
                    SpreadElementSyntax spread => Expression(spread.Expression, model, visited),
                    _ => false,
                });
            if (expression is AnonymousObjectCreationExpressionSyntax anonymous)
                return anonymous.Initializers.Any(initializer => Expression(initializer.Expression, model, visited));
            if (expression is BaseObjectCreationExpressionSyntax creation && creation.ArgumentList is { } arguments
                && arguments.Arguments.Any(argument => Expression(argument.Expression, model, visited))) return true;
            if (expression is InvocationExpressionSyntax invocation && model.GetSymbolInfo(invocation).Symbol is IMethodSymbol method)
            {
                if (method.Name == "Select" && method.ContainingType.ToDisplayString() == "System.Linq.Enumerable" && Core(method.ContainingAssembly))
                {
                    var selector = invocation.ArgumentList.Arguments.LastOrDefault()?.Expression;
                    if (selector is LambdaExpressionSyntax lambda)
                        return lambda.ExpressionBody is { } body ? Expression(body, model, visited)
                            : lambda.Block?.DescendantNodes().OfType<ReturnStatementSyntax>().Any(returned => returned.Expression is { } value && Expression(value, model, visited)) == true;
                    return selector is not null && model.GetSymbolInfo(selector).Symbol is IMethodSymbol selected && Symbol(selected, visited);
                }
                if (Symbol(method, visited)) return true;
                if (invocation.Expression is MemberAccessExpressionSyntax receiver && Expression(receiver.Expression, model, visited)) return true;
                return invocation.ArgumentList.Arguments.Any(argument => Expression(argument.Expression, model, visited));
            }
            if (model.GetSymbolInfo(expression).Symbol is { } symbol && Symbol(symbol, visited)) return true;
            return expression.ChildNodes().OfType<ExpressionSyntax>().Any(child => Expression(child, model, visited));
        }
    }
}
