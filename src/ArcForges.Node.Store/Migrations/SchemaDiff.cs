// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Migrations;

/// <summary>A column as SQLite reports it (<c>PRAGMA table_xinfo</c>).</summary>
public sealed record ColumnSchema(string Name, string Type, bool NotNull, string? DefaultValue, int PrimaryKeyPosition);

/// <summary>A table: its columns in order and its definition as stored in <c>sqlite_schema</c>.</summary>
public sealed record TableSchema(string Name, IReadOnlyList<ColumnSchema> Columns, string Sql);

/// <summary>An index: its table, uniqueness and normalized definition.</summary>
public sealed record IndexSchema(string Name, string Table, string Sql);

/// <summary>The schema of a store as SQLite reports it.</summary>
public sealed partial class SchemaSnapshot
{
    private SchemaSnapshot(IReadOnlyDictionary<string, TableSchema> tables, IReadOnlyDictionary<string, IndexSchema> indexes)
    {
        Tables = tables;
        Indexes = indexes;
    }

    /// <summary>Tables by name.</summary>
    public IReadOnlyDictionary<string, TableSchema> Tables { get; }

    /// <summary>Explicit indexes by name (automatic indexes of keys are part of their table).</summary>
    public IReadOnlyDictionary<string, IndexSchema> Indexes { get; }

    /// <summary>Reads the schema of an open database.</summary>
    public static SchemaSnapshot Capture(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        var tables = new SortedDictionary<string, TableSchema>(StringComparer.Ordinal);
        var indexes = new SortedDictionary<string, IndexSchema>(StringComparer.Ordinal);
        var objects = new List<(string Type, string Name, string Table, string Sql)>();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY name;";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                objects.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
            }
        }

        foreach (var (type, name, table, sql) in objects)
        {
            if (type == "table")
            {
                var columns = new List<ColumnSchema>();
                using var command = connection.CreateCommand();
                command.CommandText = "SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_xinfo($table) ORDER BY cid;";
                command.Parameters.AddWithValue("$table", name);
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    columns.Add(new ColumnSchema(reader.GetString(0), reader.GetString(1).ToUpperInvariant(), reader.GetInt64(2) != 0,
                        reader.IsDBNull(3) ? null : reader.GetString(3), checked((int)reader.GetInt64(4))));
                }

                tables[name] = new TableSchema(name, columns, sql);
            }
            else if (type == "index")
            {
                indexes[name] = new IndexSchema(name, table, Normalize(sql));
            }
            else
            {
                // Views and triggers are not part of the node store; listing them keeps a drop visible.
                indexes[type + ":" + name] = new IndexSchema(name, table, Normalize(sql));
            }
        }

        return new SchemaSnapshot(tables, indexes);
    }

    internal static string Normalize(string sql) => WhiteSpace().Replace(sql, " ").Trim();

    [GeneratedRegex(@"\s+", RegexOptions.CultureInvariant)]
    private static partial Regex WhiteSpace();
}

/// <summary>
/// The expand-only check of 13-distribution-updates section 6 and section 9 ("a schema diff tool fails on any drop or rename
/// in a release"). A release's migrations may add tables, add columns that are nullable or have a default, and add indexes.
/// Anything else (a dropped or renamed table, column or index; a changed column, table definition or index) is a violation;
/// such contract steps belong to a later release that raises <c>min_reader_version</c>.
/// </summary>
public static partial class SchemaDiff
{
    /// <summary>The violations of the expand-only rule between two schemas (empty when <paramref name="after"/> only expands <paramref name="before"/>).</summary>
    public static IReadOnlyList<string> ExpandOnlyViolations(SchemaSnapshot before, SchemaSnapshot after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        var violations = new List<string>();
        foreach (var (name, old) in before.Tables)
        {
            if (!after.Tables.TryGetValue(name, out var current))
            {
                violations.Add($"table {name} was dropped or renamed");
                continue;
            }

            for (var index = 0; index < old.Columns.Count; index++)
            {
                var column = old.Columns[index];
                if (index >= current.Columns.Count || !string.Equals(current.Columns[index].Name, column.Name, StringComparison.Ordinal))
                {
                    violations.Add($"column {name}.{column.Name} was dropped, renamed or moved");
                    continue;
                }

                if (current.Columns[index] != column)
                {
                    violations.Add($"column {name}.{column.Name} changed its type, nullability, default or key");
                }
            }

            foreach (var added in current.Columns.Skip(old.Columns.Count))
            {
                if (added.NotNull && added.DefaultValue is null)
                {
                    violations.Add($"column {name}.{added.Name} was added NOT NULL without a default");
                }

                if (added.PrimaryKeyPosition != 0)
                {
                    violations.Add($"column {name}.{added.Name} was added to the primary key");
                }
            }

            // ALTER TABLE ... ADD COLUMN only appends column definitions; any other change of the table text (constraints,
            // STRICT, WITHOUT ROWID) means the table was rebuilt.
            if (!IsAppendOnly(old, current))
            {
                violations.Add($"table {name} changed its definition beyond added columns");
            }
        }

        foreach (var (name, old) in before.Indexes)
        {
            if (!after.Indexes.TryGetValue(name, out var current))
            {
                violations.Add($"index {name} was dropped or renamed");
            }
            else if (!string.Equals(current.Sql, old.Sql, StringComparison.Ordinal))
            {
                violations.Add($"index {name} changed its definition");
            }
        }

        return violations;
    }

    /// <summary>
    /// The statements of a migration that cannot be expand-only: <c>DROP</c>, <c>RENAME</c>, and <c>ALTER TABLE</c> other
    /// than <c>ADD COLUMN</c>. Comments and string literals are ignored.
    /// </summary>
    public static IReadOnlyList<string> ContractStatements(string sql)
    {
        ArgumentNullException.ThrowIfNull(sql);
        var code = StripCommentsAndLiterals(sql);
        var found = new List<string>();
        foreach (var statement in code.Split(';'))
        {
            var text = SchemaSnapshot.Normalize(statement);
            if (text.Length == 0)
            {
                continue;
            }

            if (Drop().IsMatch(text) || Rename().IsMatch(text) || (AlterTable().IsMatch(text) && !AlterAddColumn().IsMatch(text)))
            {
                found.Add(text);
            }
        }

        return found;
    }

    private static bool IsAppendOnly(TableSchema before, TableSchema after)
    {
        if (string.Equals(before.Sql, after.Sql, StringComparison.Ordinal))
        {
            return after.Columns.Count == before.Columns.Count;
        }

        // ALTER TABLE ... ADD COLUMN inserts ", <column definition>" at the closing parenthesis of the column list and keeps
        // the rest of the stored text byte for byte.
        var close = ClosingParenthesis(before.Sql);
        if (close < 0 || after.Columns.Count <= before.Columns.Count)
        {
            return false;
        }

        var head = before.Sql[..close];
        var tail = before.Sql[close..];
        return after.Sql.Length > head.Length + tail.Length
            && after.Sql.StartsWith(head, StringComparison.Ordinal)
            && after.Sql.EndsWith(tail, StringComparison.Ordinal)
            && after.Sql.AsSpan(head.Length).TrimStart().StartsWith(",", StringComparison.Ordinal);
    }

    // The parenthesis that closes the column list, skipping comments and quoted text.
    private static int ClosingParenthesis(string sql)
    {
        var depth = 0;
        for (var index = 0; index < sql.Length; index++)
        {
            var character = sql[index];
            if (character == '-' && index + 1 < sql.Length && sql[index + 1] == '-')
            {
                var end = sql.IndexOf('\n', index);
                index = end < 0 ? sql.Length : end;
                continue;
            }

            if (character == '/' && index + 1 < sql.Length && sql[index + 1] == '*')
            {
                var end = sql.IndexOf("*/", index + 2, StringComparison.Ordinal);
                index = end < 0 ? sql.Length : end + 1;
                continue;
            }

            if (character is '\'' or '"' or '`' or '[')
            {
                var closing = character == '[' ? ']' : character;
                var end = sql.IndexOf(closing, index + 1);
                index = end < 0 ? sql.Length : end;
                continue;
            }

            if (character == '(')
            {
                depth++;
            }
            else if (character == ')' && --depth == 0)
            {
                return index;
            }
        }

        return -1;
    }

    private static string StripCommentsAndLiterals(string sql)
    {
        var builder = new StringBuilder(sql.Length);
        for (var index = 0; index < sql.Length; index++)
        {
            var character = sql[index];
            if (character == '-' && index + 1 < sql.Length && sql[index + 1] == '-')
            {
                while (index < sql.Length && sql[index] != '\n')
                {
                    index++;
                }

                builder.Append('\n');
            }
            else if (character == '/' && index + 1 < sql.Length && sql[index + 1] == '*')
            {
                var end = sql.IndexOf("*/", index + 2, StringComparison.Ordinal);
                index = end < 0 ? sql.Length : end + 1;
                builder.Append(' ');
            }
            else if (character == '\'')
            {
                var end = index + 1;
                while (end < sql.Length && !(sql[end] == '\'' && (end + 1 >= sql.Length || sql[end + 1] != '\'')))
                {
                    end += sql[end] == '\'' ? 2 : 1;
                }

                index = end;
                builder.Append("''");
            }
            else
            {
                builder.Append(character);
            }
        }

        return builder.ToString().ToUpper(CultureInfo.InvariantCulture);
    }

    [GeneratedRegex(@"\bDROP\b", RegexOptions.CultureInvariant)]
    private static partial Regex Drop();

    [GeneratedRegex(@"\bRENAME\b", RegexOptions.CultureInvariant)]
    private static partial Regex Rename();

    [GeneratedRegex(@"^ALTER\s+TABLE\b", RegexOptions.CultureInvariant)]
    private static partial Regex AlterTable();

    [GeneratedRegex(@"^ALTER\s+TABLE\s+\S+\s+ADD\s+(COLUMN\s+)?\S", RegexOptions.CultureInvariant)]
    private static partial Regex AlterAddColumn();
}
