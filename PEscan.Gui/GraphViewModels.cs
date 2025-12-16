using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using PEscan;

namespace PEscan.Gui;

public sealed class GraphViewModel
{
    public string Title { get; }
    public string FilePath { get; }
    public DllDependencyNode Root { get; }
    public ObservableCollection<NodeViewModel> Nodes { get; }

    public GraphViewModel(string filePath, DllDependencyNode root)
    {
        FilePath = filePath;
        Root = root;
        Title = Path.GetFileName(filePath);
        Nodes = new ObservableCollection<NodeViewModel>(new[] { new NodeViewModel(root) });
    }
}

public sealed class NodeViewModel
{
    public string Name { get; }
    public string? Path { get; }
    public ObservableCollection<NodeViewModel> Children { get; }

    public NodeViewModel(DllDependencyNode node)
    {
        Name = node.Name;
        Path = node.ResolvedPath;
        Children = new ObservableCollection<NodeViewModel>(
            node.Dependencies.Select(child => new NodeViewModel(child)));
    }
}

