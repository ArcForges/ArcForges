// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Desktop.Tests;

public sealed class MainWindowViewModelTests
{
    [Fact]
    public void StartsWithHelloWorld() => Assert.Equal("Hello, World!", new MainWindowViewModel().Greeting);

    [Theory]
    [InlineData(null, "Hello, World!")]
    [InlineData("", "Hello, World!")]
    [InlineData("  \t", "Hello, World!")]
    [InlineData("Ada", "Hello, Ada!")]
    [InlineData("  ArcForges  ", "Hello, ArcForges!")]
    [InlineData("世界 🌍", "Hello, 世界 🌍!")]
    public void GreetsTheEnteredName(string? name, string expected)
    {
        var viewModel = new MainWindowViewModel { Name = name };

        viewModel.SayHello();

        Assert.Equal(expected, viewModel.Greeting);
    }

    [Fact]
    public void NotifiesBindingsOnlyWhenValuesChange()
    {
        var viewModel = new MainWindowViewModel();
        var changes = new List<string?>();
        viewModel.PropertyChanged += (_, args) => changes.Add(args.PropertyName);

        viewModel.Name = "Ada";
        viewModel.Name = "Ada";
        Assert.Equal("Hello, World!", viewModel.Greeting);
        viewModel.SayHello();
        viewModel.SayHello();

        Assert.Equal([nameof(viewModel.Name), nameof(viewModel.Greeting)], changes);
    }
}
