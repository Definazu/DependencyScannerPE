using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using PEscan;

namespace PEscan.Gui;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<GraphViewModel> _graphs = new();

    public MainWindow()
    {
        InitializeComponent();
        GraphsTab.ItemsSource = _graphs;
    }

    private void SetStatus(string message) => StatusText.Text = message;

    private void OnChooseFile(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "EXE files (*.exe)|*.exe|All files (*.*)|*.*",
            Multiselect = false
        };

        if (dlg.ShowDialog(this) == true)
        {
            PathBox.Text = dlg.FileName;
        }
    }

    private void OnChooseDirectory(object sender, RoutedEventArgs e)
    {
        using var dlg = new System.Windows.Forms.FolderBrowserDialog();
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
        {
            PathBox.Text = dlg.SelectedPath;
        }
    }

    private async void OnAnalyze(object sender, RoutedEventArgs e)
    {
        var path = PathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(path))
        {
            MessageBox.Show(this, "Specify file (-f) or directory (-d).", "No input", MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        var formats = GetSelectedFormats().ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (formats.Count == 0)
        {
            MessageBox.Show(this, "Select at least one report format.", "No formats", MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        bool skipSystem = FilteredCheck.IsChecked == true;

        List<string> files = new();
        if (File.Exists(path))
        {
            files.Add(Path.GetFullPath(path));
        }
        else if (Directory.Exists(path))
        {
            files = Directory.GetFiles(path, "*.exe", SearchOption.TopDirectoryOnly)
                .Take(10)
                .Select(Path.GetFullPath)
                .ToList();

            if (files.Count == 0)
            {
                MessageBox.Show(this, "No EXE files found in directory.", "No files", MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }
        }
        else
        {
            MessageBox.Show(this, "Path not found.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        AnalyzeButtonEnabled(false);
        SetStatus("Analyzing...");
        _graphs.Clear();

        var errors = new ConcurrentBag<string>();
        var results = new ConcurrentBag<FileAnalysisResult>();

        var tasks = files.Select(file => Task.Run(() =>
        {
            try
            {
                var pe = PeParser.Parse(file);
                var resolver = new DependencyResolver(file, maxDepth: 10, skipSystemDlls: skipSystem);
                var root = resolver.BuildDependencyTree(pe);
                results.Add(new FileAnalysisResult(file, root));
            }
            catch (Exception ex)
            {
                errors.Add($"{file}: {ex.Message}");
            }
        })).ToArray();

        await Task.WhenAll(tasks);

        foreach (var res in results)
        {
            _graphs.Add(new GraphViewModel(res.FilePath, res.DependencyTree));
        }

        if (_graphs.Count > 0)
        {
            GraphsTab.SelectedIndex = 0;
            SetStatus(errors.Count == 0 ? "Ready." : $"Ready with {errors.Count} error(s).");
        }
        else
        {
            SetStatus("No graphs.");
        }

        if (errors.Count > 0)
        {
            MessageBox.Show(this, string.Join(Environment.NewLine, errors), "Errors", MessageBoxButton.OK,
                MessageBoxImage.Error);
        }

        AnalyzeButtonEnabled(true);
    }

    private void AnalyzeButtonEnabled(bool enabled)
    {
        if (AnalyzeButton != null) AnalyzeButton.IsEnabled = enabled;
        if (PathBox != null) PathBox.IsEnabled = enabled;
        if (GraphsTab != null) GraphsTab.IsEnabled = enabled;
        if (FormatJson != null) FormatJson.IsEnabled = enabled;
        if (FormatTxt != null) FormatTxt.IsEnabled = enabled;
        if (FormatCsv != null) FormatCsv.IsEnabled = enabled;
        if (FormatDot != null) FormatDot.IsEnabled = enabled;
        if (FilteredCheck != null) FilteredCheck.IsEnabled = enabled;
    }

    private IEnumerable<string> GetSelectedFormats()
    {
        if (FormatJson.IsChecked == true) yield return "json";
        if (FormatTxt.IsChecked == true) yield return "txt";
        if (FormatCsv.IsChecked == true) yield return "csv";
        if (FormatDot.IsChecked == true) yield return "dot";
    }

    private GraphViewModel? CurrentGraph()
    {
        return GraphsTab.SelectedItem as GraphViewModel;
    }

    private async void OnSaveJson(object sender, RoutedEventArgs e) => await SaveCurrent("json");
    private async void OnSaveTxt(object sender, RoutedEventArgs e) => await SaveCurrent("txt");
    private async void OnSaveCsv(object sender, RoutedEventArgs e) => await SaveCurrent("csv");
    private async void OnSaveDot(object sender, RoutedEventArgs e) => await SaveCurrent("dot");

    private async Task SaveCurrent(string format)
    {
        var graph = CurrentGraph();
        if (graph == null)
            return;

        var dlg = new SaveFileDialog
        {
            FileName = $"{Path.GetFileNameWithoutExtension(graph.FilePath)}.deps.{format}",
            Filter = format.ToUpperInvariant() + " files|*." + format + "|All files|*.*"
        };

        if (dlg.ShowDialog(this) != true)
            return;

        string content = format switch
        {
            "json" => ReportGenerators.ToJson(graph.Root),
            "txt" => ReportGenerators.ToText(graph.Root),
            "csv" => ReportGenerators.ToCsv(graph.Root),
            "dot" => ReportGenerators.ToDot(graph.Root),
            _ => throw new InvalidOperationException("Unknown format")
        };

        await File.WriteAllTextAsync(dlg.FileName, content);
        SetStatus($"Saved {format.ToUpperInvariant()}");
    }
}

