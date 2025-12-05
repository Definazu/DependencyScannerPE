using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PEscan;

public static class ReportGenerators
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string ToJson(DllDependencyNode root)
    {
        return JsonSerializer.Serialize(root, JsonOptions);
    }

    public static string ToText(DllDependencyNode root)
    {
        var sb = new StringBuilder();
        WriteNodeText(root, sb, "");
        return sb.ToString();
    }

    private static void WriteNodeText(DllDependencyNode node, StringBuilder sb, string indent)
    {
        sb.Append(indent)
            .Append("- ")
            .Append(node.Name);

        if (!string.IsNullOrEmpty(node.ResolvedPath))
        {
            sb.Append(" (").Append(node.ResolvedPath).Append(')');
        }

        sb.AppendLine();

        var nextIndent = indent + "  ";
        foreach (var child in node.Dependencies)
        {
            WriteNodeText(child, sb, nextIndent);
        }
    }

    public static string ToCsv(DllDependencyNode root)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Depth,Parent,Name,Path");
        WriteNodeCsv(root, sb, parent: null);
        return sb.ToString();
    }

    private static void WriteNodeCsv(DllDependencyNode node, StringBuilder sb, string? parent)
    {
        string Safe(string? s) => s?.Replace("\"", "\"\"") ?? string.Empty;

        sb.Append(node.Depth).Append(',')
            .Append('"').Append(Safe(parent)).Append('"').Append(',')
            .Append('"').Append(Safe(node.Name)).Append('"').Append(',')
            .Append('"').Append(Safe(node.ResolvedPath)).Append('"')
            .AppendLine();

        foreach (var child in node.Dependencies)
        {
            WriteNodeCsv(child, sb, node.Name);
        }
    }

    public static string ToDot(DllDependencyNode root)
    {
        var sb = new StringBuilder();
        sb.AppendLine("digraph Dependencies {");
        sb.AppendLine("  rankdir=LR;");
        sb.AppendLine("  node [shape=box, fontname=\"Consolas\"];");

        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Dfs(DllDependencyNode node)
        {
            if (!visited.Add(node.Name))
                return;

            foreach (var child in node.Dependencies)
            {
                sb.Append("  \"").Append(node.Name).Append("\" -> \"")
                    .Append(child.Name).AppendLine("\";");
                Dfs(child);
            }
        }

        Dfs(root);
        sb.AppendLine("}");
        return sb.ToString();
    }
}


