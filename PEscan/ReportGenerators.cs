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

    public static string ToJson(CombinedReport report)
    {
        return JsonSerializer.Serialize(report, JsonOptions);
    }

    public static string ToText(CombinedReport report)
    {
        var sb = new StringBuilder();
        foreach (var fileResult in report.Files)
        {
            sb.AppendLine($"=== {Path.GetFileName(fileResult.FilePath)} ===");
            sb.AppendLine($"Path: {fileResult.FilePath}");
            sb.AppendLine();
            WriteNodeText(fileResult.DependencyTree, sb, "");
            sb.AppendLine();
        }
        return sb.ToString();
    }

    public static string ToCsv(CombinedReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("File,Depth,Parent,Name,Path");
        foreach (var fileResult in report.Files)
        {
            var fileName = Path.GetFileName(fileResult.FilePath);
            WriteNodeCsvForFile(fileResult.DependencyTree, sb, fileName, parent: null);
        }
        return sb.ToString();
    }

    private static void WriteNodeCsvForFile(DllDependencyNode node, StringBuilder sb, string fileName, string? parent)
    {
        string Safe(string? s) => s?.Replace("\"", "\"\"") ?? string.Empty;

        sb.Append('"').Append(Safe(fileName)).Append('"').Append(',')
            .Append(node.Depth).Append(',')
            .Append('"').Append(Safe(parent)).Append('"').Append(',')
            .Append('"').Append(Safe(node.Name)).Append('"').Append(',')
            .Append('"').Append(Safe(node.ResolvedPath)).Append('"')
            .AppendLine();

        foreach (var child in node.Dependencies)
        {
            WriteNodeCsvForFile(child, sb, fileName, node.Name);
        }
    }

    public static string ToDot(CombinedReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("digraph Dependencies {");
        sb.AppendLine("  rankdir=LR;");
        sb.AppendLine("  node [shape=box, fontname=\"Consolas\"];");

        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var fileResult in report.Files)
        {
            var fileName = Path.GetFileNameWithoutExtension(fileResult.FilePath);
            
            void Dfs(DllDependencyNode node, string? filePrefix = null)
            {
                string nodeId = filePrefix != null ? $"{filePrefix}_{node.Name}" : node.Name;
                
                if (!visited.Add(nodeId))
                    return;

                foreach (var child in node.Dependencies)
                {
                    string childId = filePrefix != null ? $"{filePrefix}_{child.Name}" : child.Name;
                    sb.Append("  \"").Append(nodeId).Append("\" -> \"")
                        .Append(childId).AppendLine("\";");
                    Dfs(child, filePrefix);
                }
            }

            Dfs(fileResult.DependencyTree, report.Files.Count > 1 ? fileName : null);
        }

        sb.AppendLine("}");
        return sb.ToString();
    }
}


