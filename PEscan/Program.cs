using PEscan;
using System.Collections.Concurrent;

if (args.Length == 0)
{
    Console.WriteLine("Using: PEscan.exe <file1.exe> [file2.exe ...] [-formats json,txt,csv,dot] [-out <outputDirectory>] [--filtered]");
    return;
}

var formats = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "json", "txt", "csv", "dot" };
string outputDirectory = Environment.CurrentDirectory;
bool skipSystemDlls = false;

var inputFiles = new List<string>();
for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
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
                inputFiles.Add(args[i]);
            break;
    }
}

if (inputFiles.Count == 0)
{
    Console.Error.WriteLine("Input EXE files not specified.");
    return;
}

Directory.CreateDirectory(outputDirectory);

var parallelOptions = new ParallelOptions
{
    MaxDegreeOfParallelism = Math.Min(10, Environment.ProcessorCount)
};

var errors = new ConcurrentBag<string>();

Parallel.ForEach(inputFiles, parallelOptions, exePath =>
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

        var baseName = Path.GetFileNameWithoutExtension(fullPath);

        if (formats.Contains("json"))
        {
            var json = ReportGenerators.ToJson(rootNode);
            File.WriteAllText(Path.Combine(outputDirectory, baseName + ".deps.json"), json);
        }

        if (formats.Contains("txt"))
        {
            var txt = ReportGenerators.ToText(rootNode);
            File.WriteAllText(Path.Combine(outputDirectory, baseName + ".deps.txt"), txt);
        }

        if (formats.Contains("csv"))
        {
            var csv = ReportGenerators.ToCsv(rootNode);
            File.WriteAllText(Path.Combine(outputDirectory, baseName + ".deps.csv"), csv);
        }

        if (formats.Contains("dot"))
        {
            var dot = ReportGenerators.ToDot(rootNode);
            File.WriteAllText(Path.Combine(outputDirectory, baseName + ".deps.dot"), dot);
        }
    }
    catch (Exception ex)
    {
        errors.Add($"Raw error in analysis {exePath}: {ex}");
    }
});

foreach (var e in errors)
{
    Console.Error.WriteLine(e);
}

Console.WriteLine("End.");
