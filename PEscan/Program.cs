using PEscan;
using System.Collections.Concurrent;
using System.Collections.Immutable;

if (args.Length == 0)
{
    Console.WriteLine("Using: PEscan.exe [-f <file.exe> | -d <directory>] [-formats json,txt,csv,dot] [-out <outputDirectory>] [--filtered]");
    Console.WriteLine("  -f, --file      : Path to a single EXE file");
    Console.WriteLine("  -d, --directory : Directory containing EXE files (up to 10 files)");
    return;
}

var formats = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "json", "txt", "csv", "dot" };
string outputDirectory = Environment.CurrentDirectory;
bool skipSystemDlls = false;

var inputFiles = new List<string>();
string? singleFile = null;
string? directory = null;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "-f":
        case "--file":
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine("No file path specified after -f/--file.");
                return;
            }
            singleFile = args[++i];
            break;

        case "-d":
        case "--directory":
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine("No directory path specified after -d/--directory.");
                return;
            }
            directory = args[++i];
            break;

        case "-formats":
        case "--formats":
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine("No list of formats after -formats.");
                return;
            }
            formats = args[++i].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            break;

        case "-out":
        case "--out":
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine("Directory not specified after -out.");
                return;
            }
            outputDirectory = args[++i];
            break;

        case "--filtered":
            skipSystemDlls = true;
            break;

        default:
            if (!args[i].StartsWith('-'))
            {
                inputFiles.Add(args[i]);
            }
            break;
    }
}

if (singleFile != null)
{
    var fullPath = Path.GetFullPath(singleFile);
    if (!File.Exists(fullPath))
    {
        Console.Error.WriteLine($"File not found: {fullPath}");
        return;
    }
    inputFiles.Add(fullPath);
}
else if (directory != null)
{
    var dirPath = Path.GetFullPath(directory);
    if (!Directory.Exists(dirPath))
    {
        Console.Error.WriteLine($"Directory not found: {dirPath}");
        return;
    }

    var exeFiles = Directory.GetFiles(dirPath, "*.exe", SearchOption.TopDirectoryOnly)
        .Take(10)
        .ToList();

    if (exeFiles.Count == 0)
    {
        Console.Error.WriteLine($"No EXE files found in directory: {dirPath}");
        return;
    }

    inputFiles.AddRange(exeFiles);
    Console.WriteLine($"Found {exeFiles.Count} EXE file(s) in directory: {dirPath}");
}

if (inputFiles.Count == 0)
{
    Console.Error.WriteLine("Input EXE files not specified. Use -f/--file or -d/--directory.");
    return;
}

Directory.CreateDirectory(outputDirectory);

var errors = new ConcurrentBag<string>();
var results = new ConcurrentBag<FileAnalysisResult>();

var tasks = inputFiles.Select(exePath => Task.Run(() =>
{
    try
    {
        var fullPath = Path.GetFullPath(exePath);
        if (!File.Exists(fullPath))
        {
            errors.Add($"File not found: {fullPath}");
            return;
        }

        Console.WriteLine($"Analysis: {fullPath}");

        PeFileInfo peInfo;
        try
        {
            peInfo = PeParser.Parse(fullPath);
        }
        catch (Exception ex)
        {
            errors.Add($"Error parsing PE-file {fullPath}: {ex.Message}");
            return;
        }

        var resolver = new DependencyResolver(fullPath, maxDepth: 10, skipSystemDlls: skipSystemDlls);
        var rootNode = resolver.BuildDependencyTree(peInfo);

        results.Add(new FileAnalysisResult(fullPath, rootNode));
        Console.WriteLine($"Completed: {fullPath}");
    }
    catch (Exception ex)
    {
        errors.Add($"Raw error in analysis {exePath}: {ex}");
    }
})).ToArray();

await Task.WhenAll(tasks);

foreach (var e in errors)
{
    Console.Error.WriteLine(e);
}

if (results.Count > 0)
{
    var combinedReport = new CombinedReport(results.ToImmutableArray());

    if (formats.Contains("json"))
    {
        var json = ReportGenerators.ToJson(combinedReport);
        await File.WriteAllTextAsync(Path.Combine(outputDirectory, "combined.deps.json"), json);
        Console.WriteLine($"Generated: combined.deps.json");
    }

    if (formats.Contains("txt"))
    {
        var txt = ReportGenerators.ToText(combinedReport);
        await File.WriteAllTextAsync(Path.Combine(outputDirectory, "combined.deps.txt"), txt);
        Console.WriteLine($"Generated: combined.deps.txt");
    }

    if (formats.Contains("csv"))
    {
        var csv = ReportGenerators.ToCsv(combinedReport);
        await File.WriteAllTextAsync(Path.Combine(outputDirectory, "combined.deps.csv"), csv);
        Console.WriteLine($"Generated: combined.deps.csv");
    }

    if (formats.Contains("dot"))
    {
        var dot = ReportGenerators.ToDot(combinedReport);
        await File.WriteAllTextAsync(Path.Combine(outputDirectory, "combined.deps.dot"), dot);
        Console.WriteLine($"Generated: combined.deps.dot");
    }
}

Console.WriteLine($"End. Processed {results.Count} file(s).");
