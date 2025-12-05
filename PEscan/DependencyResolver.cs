using System.Collections.Concurrent;
using System.Collections.Immutable;

namespace PEscan;

/// <summary>
/// Рекурсивное разрешение зависимостей DLL с учётом порядка поиска Windows
/// </summary>
public sealed class DependencyResolver
{
    private readonly int _maxDepth;
    private readonly string _exeDirectory;
    private readonly IReadOnlyList<string> _searchPaths;

    public DependencyResolver(string exePath, int maxDepth = 10)
    {
        _maxDepth = maxDepth;
        _exeDirectory = Path.GetDirectoryName(Path.GetFullPath(exePath)) ?? Environment.CurrentDirectory;

        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        var pathDirs = pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        _searchPaths = new[] { _exeDirectory, system32 }
            .Concat(pathDirs)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public DllDependencyNode BuildDependencyTree(PeFileInfo rootPe)
    {
        var visited = new ConcurrentDictionary<string, DllDependencyNode>(StringComparer.OrdinalIgnoreCase);
        return ResolveDllInternal(rootPe.FilePath, null, 0, visited);
    }

    private DllDependencyNode ResolveDllInternal(string modulePathOrName, string? logicalName, int depth,
        ConcurrentDictionary<string, DllDependencyNode> visited)
    {
        if (depth > _maxDepth)
        {
            return new DllDependencyNode(logicalName ?? modulePathOrName, null, Array.Empty<DllDependencyNode>(), depth);
        }

        string? resolvedPath = ResolvePath(modulePathOrName);
        string key = resolvedPath ?? modulePathOrName;

        if (visited.TryGetValue(key, out var existing))
        {
            // цикл / уже посещённый модуль
            return new DllDependencyNode(existing.Name, existing.ResolvedPath, Array.Empty<DllDependencyNode>(), depth);
        }

        var placeholder = new DllDependencyNode(logicalName ?? Path.GetFileName(key), resolvedPath, Array.Empty<DllDependencyNode>(), depth);
        visited[key] = placeholder;

        if (resolvedPath is null || !File.Exists(resolvedPath))
        {
            return placeholder;
        }

        PeFileInfo peInfo;
        try
        {
            peInfo = PeParser.Parse(resolvedPath);
        }
        catch
        {
            // повреждённый или неподдерживаемый файл
            return placeholder;
        }

        var children = new List<DllDependencyNode>();
        foreach (var dllName in peInfo.ImportedDlls)
        {
            var child = ResolveDllInternal(dllName, dllName, depth + 1, visited);
            children.Add(child);
        }

        var node = new DllDependencyNode(logicalName ?? Path.GetFileName(key), resolvedPath,
            children.ToImmutableArray(), depth);
        visited[key] = node;
        return node;
    }

    private string? ResolvePath(string dllNameOrPath)
    {
        if (File.Exists(dllNameOrPath))
            return Path.GetFullPath(dllNameOrPath);

        foreach (var dir in _searchPaths)
        {
            var candidate = Path.Combine(dir, dllNameOrPath);
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }
}


