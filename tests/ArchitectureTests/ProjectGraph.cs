// SPDX-License-Identifier: AGPL-3.0-only

using System.Xml.Linq;

namespace ArcForges.Tests.ArchitectureTests;

/// <summary>
/// The declared dependency graph of the production projects under <c>src/</c>.
/// </summary>
/// <remarks>
/// This engine exists because emitted assembly metadata is not a sound source for reference-direction
/// rules: the C# compiler prunes assembly references that a project declares but never uses, so a
/// project can legitimately reference a database provider and still emit no reference to it. The
/// authoritative statement of "project A depends on B" is the declared ProjectReference/PackageReference
/// graph, and the rules that matter are about its <em>transitive closure</em> — an indirect
/// Domain to DB-provider edge is exactly as forbidden as a direct one.
/// </remarks>
internal sealed class ProjectGraph
{
    private readonly Dictionary<string, ProjectNode> _nodes;

    private ProjectGraph(Dictionary<string, ProjectNode> nodes) => _nodes = nodes;

    internal IReadOnlyCollection<ProjectNode> Nodes => _nodes.Values;

    /// <summary>Builds the graph from every <c>*.csproj</c> beneath <paramref name="sourceRoot"/>.</summary>
    internal static ProjectGraph Load(string sourceRoot)
    {
        var nodes = new Dictionary<string, ProjectNode>(StringComparer.Ordinal);
        foreach (var project in Directory.EnumerateFiles(sourceRoot, "*.csproj", SearchOption.AllDirectories))
        {
            var name = Path.GetFileNameWithoutExtension(project);
            var document = XDocument.Load(project);

            var projectReferences = document.Descendants("ProjectReference")
                .Select(element => element.Attribute("Include")?.Value)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => Path.GetFileNameWithoutExtension(value!.Replace('\\', Path.DirectorySeparatorChar)))
                .Where(value => !string.IsNullOrEmpty(value))
                .ToHashSet(StringComparer.Ordinal);

            var packageReferences = document.Descendants("PackageReference")
                .Select(element => element.Attribute("Include")?.Value)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value!)
                .ToHashSet(StringComparer.Ordinal);

            nodes[name] = new ProjectNode(name, project, projectReferences, packageReferences);
        }

        return new ProjectGraph(nodes);
    }

    internal ProjectNode this[string name] => _nodes[name];

    internal bool Contains(string name) => _nodes.ContainsKey(name);

    internal IEnumerable<ProjectNode> Where(Func<ProjectNode, bool> predicate) => _nodes.Values.Where(predicate);

    /// <summary>
    /// Every project reachable from <paramref name="name"/>, excluding the project itself. Cycles cannot
    /// occur in a valid MSBuild graph but the walk is guarded anyway so a malformed fixture cannot hang.
    /// </summary>
    internal IReadOnlyCollection<string> TransitiveProjects(string name)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var pending = new Stack<string>();
        pending.Push(name);

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            if (!_nodes.TryGetValue(current, out var node))
            {
                continue;
            }

            foreach (var reference in node.ProjectReferences)
            {
                if (seen.Add(reference))
                {
                    pending.Push(reference);
                }
            }
        }

        seen.Remove(name);
        return seen;
    }

    /// <summary>Every package reachable from <paramref name="name"/>, directly or through a project edge.</summary>
    internal IReadOnlyCollection<string> TransitivePackages(string name)
    {
        var packages = new HashSet<string>(StringComparer.Ordinal);
        if (_nodes.TryGetValue(name, out var self))
        {
            packages.UnionWith(self.PackageReferences);
        }

        foreach (var project in TransitiveProjects(name))
        {
            if (_nodes.TryGetValue(project, out var node))
            {
                packages.UnionWith(node.PackageReferences);
            }
        }

        return packages;
    }

    /// <summary>
    /// The shortest declared path from <paramref name="from"/> to <paramref name="to"/>, rendered for a
    /// failure message. Returns the two endpoints joined directly when no intermediate hop exists.
    /// </summary>
    internal string DescribePath(string from, string to)
    {
        var previous = new Dictionary<string, string>(StringComparer.Ordinal);
        var queue = new Queue<string>();
        queue.Enqueue(from);
        previous[from] = from;

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            if (!_nodes.TryGetValue(current, out var node))
            {
                continue;
            }

            foreach (var next in node.ProjectReferences.Concat(node.PackageReferences))
            {
                if (previous.ContainsKey(next))
                {
                    continue;
                }

                previous[next] = current;
                if (string.Equals(next, to, StringComparison.Ordinal))
                {
                    var path = new List<string> { to };
                    var cursor = current;
                    while (!string.Equals(cursor, from, StringComparison.Ordinal))
                    {
                        path.Add(cursor);
                        cursor = previous[cursor];
                    }

                    path.Reverse();
                    return string.Join(" -> ", path);
                }

                queue.Enqueue(next);
            }
        }

        return to;
    }
}

internal sealed record ProjectNode(
    string Name,
    string Path,
    IReadOnlySet<string> ProjectReferences,
    IReadOnlySet<string> PackageReferences);
