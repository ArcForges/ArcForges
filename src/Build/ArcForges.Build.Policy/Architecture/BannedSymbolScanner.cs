// SPDX-License-Identifier: AGPL-3.0-only

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace ArcForges.Build.Policy.Architecture;

/// <summary>Semantic symbol checks: aliases and qualified spellings resolve to the same policy decision.</summary>
internal static class BannedSymbolScanner
{
    private static readonly string[] ProviderPrefixes = ["Azure", "Amazon", "OpenAI", "Cloudflare"];
    private static readonly string[] SensitiveParts = ["secret", "password", "credential", "accessToken", "prompt", "contentBody", "messageBody"];
    private static readonly string[] MoneyParts = ["money", "credit", "price", "balance", "budget"];
    public static IReadOnlyList<PolicyFinding> Scan(CSharpCompilation compilation, ProjectClassification project)
    {
        ArgumentNullException.ThrowIfNull(compilation);
        ArgumentNullException.ThrowIfNull(project);
        var findings = new List<PolicyFinding>();
        foreach (var tree in compilation.SyntaxTrees)
        {
            var model = compilation.GetSemanticModel(tree);
            foreach (var node in tree.GetRoot().DescendantNodes())
            {
                if (node is InvocationExpressionSyntax invocation)
                {
                    var symbol = model.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                    if (symbol is null)
                    {
                        if (project.Aot && model.GetTypeInfo(invocation).Type?.TypeKind == TypeKind.Dynamic)
                        {
                            Add("BAN-REFLECTION", invocation, "Dynamic invocation requires runtime binding on an AOT path.");
                        }
                        else if (invocation.Expression is not IdentifierNameSyntax { Identifier.ValueText: "nameof" })
                        {
                            throw new InvalidOperationException("Unresolved invocation cannot be audited: " + invocation.GetLocation());
                        }

                        continue;
                    }

                    string type = symbol.ContainingType.ToDisplayString();
                    string space = symbol.ContainingNamespace.ToDisplayString();
                    if (project.Aot && IsReflection(type, symbol.Name))
                    {
                        Add("BAN-REFLECTION", invocation, "Reflection entry point is reachable on an AOT path: " + symbol);
                    }

                    if (space.StartsWith("System.Reflection.Emit", StringComparison.Ordinal)
                        || (space.StartsWith("System.Linq.Expressions", StringComparison.Ordinal) && symbol.Name == "Compile"))
                    {
                        Add("BAN-CODEGEN", invocation, "Runtime code generation is forbidden: " + symbol);
                    }

                    if (IsAsyncPath(invocation, model) && IsBlocking(type, symbol.Name))
                    {
                        Add("BAN-BLOCKING", invocation, "Blocking wait in an asynchronous path: " + symbol);
                    }

                    if (!IsAdapter(project.Role) && IsProvider(space))
                    {
                        Add("BAN-PROVIDER", invocation, "Provider SDK call outside its adapter: " + symbol);
                    }

                    if (IsLogging(type, space, symbol.Name) && invocation.ArgumentList.Arguments.Any(argument =>
                        Sensitive(argument.Expression, model)))
                    {
                        Add("BAN-LOGGING", invocation, "A secret-bearing or content value reaches a logging call.");
                    }
                }

                if (node is BaseObjectCreationExpressionSyntax creation && model.GetTypeInfo(creation).Type is { } created)
                {
                    string space = created.ContainingNamespace.ToDisplayString();
                    if (space.StartsWith("System.Reflection.Emit", StringComparison.Ordinal))
                    {
                        Add("BAN-CODEGEN", creation, "Runtime code generation type: " + created);
                    }

                    if (!IsAdapter(project.Role) && IsProvider(space))
                    {
                        Add("BAN-PROVIDER", creation, "Provider SDK construction outside its adapter: " + created);
                    }
                }

                if (node is MemberAccessExpressionSyntax member && IsAsyncPath(member, model)
                    && model.GetSymbolInfo(member).Symbol is IPropertySymbol property
                    && property.Name == "Result" && property.ContainingNamespace.ToDisplayString() == "System.Threading.Tasks")
                {
                    Add("BAN-BLOCKING", member, "Synchronous Task/ValueTask result access in an asynchronous path.");
                }

                if (node is VariableDeclaratorSyntax variable && variable.Parent?.Parent is FieldDeclarationSyntax
                    && model.GetDeclaredSymbol(variable) is IFieldSymbol field
                    && IsRawPointer(field.Type)
                    && (project.Role != ProjectRole.NativeAdapter || field.ContainingType.TypeKind != TypeKind.Struct))
                {
                    Add("BAN-POINTER", variable, "Raw native pointer field outside the native lifetime adapter.");
                }

                if (node is ExpressionSyntax expression && IsMoneyContext(expression, model, project)
                    && model.GetTypeInfo(expression).Type?.SpecialType is SpecialType.System_Single or SpecialType.System_Double)
                {
                    Add("BAN-MONEY", expression, "Binary floating-point value in a money or credit path.");
                }
            }

            void Add(string rule, SyntaxNode node, string message)
            {
                findings.Add(new PolicyFinding(rule, tree.FilePath, message,
                    node.GetLocation().GetLineSpan().StartLinePosition.Line + 1));
            }
        }

        return findings.Distinct().ToArray();
    }

    public static bool IsNativePointer(ITypeSymbol type) => IsRawPointer(type)
        || Inherits(type, "System.Runtime.InteropServices.SafeHandle");

    private static bool IsRawPointer(ITypeSymbol type) => type.TypeKind == TypeKind.Pointer
        || type.SpecialType is SpecialType.System_IntPtr or SpecialType.System_UIntPtr;

    private static bool Inherits(ITypeSymbol type, string name)
    {
        for (var current = type as INamedTypeSymbol; current is not null; current = current.BaseType)
        {
            if (current.ToDisplayString() == name)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsAdapter(ProjectRole role) => role is ProjectRole.Infrastructure
        or ProjectRole.LocalRpcAdapter or ProjectRole.PublicApiAdapter or ProjectRole.NativeAdapter;

    private static bool IsProvider(string space) => ProviderPrefixes
        .Any(prefix => space == prefix || space.StartsWith(prefix + ".", StringComparison.Ordinal));

    private static bool IsReflection(string type, string method) =>
        (type == "System.Type" && (method == "GetType" || method.StartsWith("GetMethod", StringComparison.Ordinal)
            || method.StartsWith("GetPropert", StringComparison.Ordinal) || method.StartsWith("GetField", StringComparison.Ordinal)
            || method.StartsWith("GetConstructor", StringComparison.Ordinal) || method.StartsWith("GetMember", StringComparison.Ordinal)
            || method is "InvokeMember" or "MakeGenericType"))
        || (type == "System.Activator" && method.StartsWith("CreateInstance", StringComparison.Ordinal))
        || (type == "System.Reflection.Assembly" && (method.StartsWith("Load", StringComparison.Ordinal) || method is "GetType" or "GetTypes"))
        || (type.StartsWith("System.Reflection.", StringComparison.Ordinal) && method is "Invoke" or "GetValue" or "SetValue" or "MakeGenericMethod");

    private static bool IsBlocking(string type, string method) =>
        (type.StartsWith("System.Threading.Tasks.", StringComparison.Ordinal) && method is "Wait" or "WaitAll" or "WaitAny")
        || (type.StartsWith("System.Runtime.CompilerServices.TaskAwaiter", StringComparison.Ordinal) && method == "GetResult")
        || (type.StartsWith("System.Runtime.CompilerServices.ValueTaskAwaiter", StringComparison.Ordinal) && method == "GetResult")
        || (type.StartsWith("System.Runtime.CompilerServices.ConfiguredTaskAwaitable", StringComparison.Ordinal) && method == "GetResult")
        || (type.StartsWith("System.Runtime.CompilerServices.ConfiguredValueTaskAwaitable", StringComparison.Ordinal) && method == "GetResult")
        || (type == "System.Threading.Thread" && method == "Sleep");

    private static bool IsAsyncPath(SyntaxNode node, SemanticModel model)
    {
        foreach (var scope in node.Ancestors())
        {
            if (scope is AnonymousFunctionExpressionSyntax function)
            {
                return !function.AsyncKeyword.IsKind(SyntaxKind.None)
                    || (model.GetSymbolInfo(function).Symbol is IMethodSymbol lambda
                        && lambda.ReturnType.ContainingNamespace?.ToDisplayString() == "System.Threading.Tasks");
            }

            if (scope is LocalFunctionStatementSyntax local)
            {
                return local.Modifiers.Any(SyntaxKind.AsyncKeyword)
                    || model.GetDeclaredSymbol(local)?.ReturnType.ContainingNamespace?.ToDisplayString() == "System.Threading.Tasks";
            }

            if (scope is MethodDeclarationSyntax method)
            {
                return method.Modifiers.Any(SyntaxKind.AsyncKeyword)
                    || model.GetDeclaredSymbol(method)?.ReturnType.ContainingNamespace?.ToDisplayString() == "System.Threading.Tasks";
            }
        }

        return false;
    }

    private static bool IsLogging(string type, string space, string method) =>
        (space.StartsWith("Microsoft.Extensions.Logging", StringComparison.Ordinal) && method.StartsWith("Log", StringComparison.Ordinal))
        || ((type is "System.Console" or "System.Diagnostics.Debug" or "System.Diagnostics.Trace")
            && method.StartsWith("Write", StringComparison.Ordinal));

    private static bool Sensitive(ExpressionSyntax expression, SemanticModel model) => Sensitive(expression, model, new HashSet<ISymbol>(SymbolEqualityComparer.Default));

    private static bool Sensitive(ExpressionSyntax expression, SemanticModel model, HashSet<ISymbol> visited) =>
        expression.DescendantNodesAndSelf().OfType<ExpressionSyntax>().Any(node =>
        {
            var symbol = model.GetSymbolInfo(node).Symbol;
            var type = model.GetTypeInfo(node).Type;
            if (SensitiveName(symbol?.Name ?? "") || SensitiveName(type?.Name ?? ""))
            {
                return true;
            }

            return symbol is ILocalSymbol local && visited.Add(local)
                && local.DeclaringSyntaxReferences.Select(reference => reference.GetSyntax()).OfType<VariableDeclaratorSyntax>()
                    .Any(variable => variable.Initializer is { } initializer && Sensitive(initializer.Value, model, visited));
        });

    private static bool SensitiveName(string name) => SensitiveParts
        .Any(part => name.Contains(part, StringComparison.OrdinalIgnoreCase));

    private static bool IsMoneyContext(ExpressionSyntax expression, SemanticModel model, ProjectClassification project)
    {
        if (project.Module is "Commerce" or "Entitlement")
        {
            return true;
        }

        for (SyntaxNode? node = expression; node is not null; node = node.Parent)
        {
            string name = node switch
            {
                VariableDeclaratorSyntax variable => variable.Identifier.ValueText,
                PropertyDeclarationSyntax property => property.Identifier.ValueText,
                MethodDeclarationSyntax method => method.Identifier.ValueText,
                TypeDeclarationSyntax declaration => declaration.Identifier.ValueText,
                _ => "",
            };
            if (MoneyParts.Any(part => name.Contains(part, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        string symbolName = model.GetSymbolInfo(expression).Symbol?.Name ?? "";
        return symbolName.Contains("money", StringComparison.OrdinalIgnoreCase)
            || symbolName.Contains("credit", StringComparison.OrdinalIgnoreCase);
    }
}
