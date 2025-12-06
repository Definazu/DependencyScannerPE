using System.Collections.Immutable;

namespace PEscan;

/// <summary>
/// Базовая инфа о PE-файле
/// </summary>
public sealed record PeFileInfo(
    string FilePath,
    bool Is64Bit,
    ImmutableArray<string> ImportedDlls);

/// <summary>
/// Нода графа зависимостей DLL
/// </summary>
public sealed record DllDependencyNode(
    string Name,
    string? ResolvedPath,
    IReadOnlyCollection<DllDependencyNode> Dependencies,
    int Depth);

/// <summary>
/// Результат анализа одного файла
/// </summary>
public sealed record FileAnalysisResult(
    string FilePath,
    DllDependencyNode DependencyTree);

/// <summary>
/// Объединённый отчёт по нескольким файлам
/// </summary>
public sealed record CombinedReport(
    IReadOnlyCollection<FileAnalysisResult> Files);


