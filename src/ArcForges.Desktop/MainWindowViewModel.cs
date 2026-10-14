// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace ArcForges.Desktop;

public sealed class MainWindowViewModel : INotifyPropertyChanged
{
    private string? _name;
    private string _greeting = "Hello, World!";

    public event PropertyChangedEventHandler? PropertyChanged;

    public string? Name
    {
        get => _name;
        set
        {
            if (_name == value)
            {
                return;
            }

            _name = value;
            OnPropertyChanged();
        }
    }

    public string Greeting
    {
        get => _greeting;
        private set
        {
            if (_greeting == value)
            {
                return;
            }

            _greeting = value;
            OnPropertyChanged();
        }
    }

    public void SayHello() => Greeting = $"Hello, {(string.IsNullOrWhiteSpace(Name) ? "World" : Name.Trim())}!";

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
