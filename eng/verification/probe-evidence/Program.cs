// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using Avalonia.Controls;
using Avalonia.Data;

var table = new TableView
{
    CanUserResizeColumns = false,
    ItemsSource = new ObservableCollection<OperatorActivityRow>
    {
        new("probe-event", "Native AOT candidate probe"),
    },
};

table.Columns.Add(new TableViewColumn
{
    Header = "Event",
    Binding = CompiledBinding.Create<OperatorActivityRow, string>(static row => row.Event),
});
table.Columns.Add(new TableViewColumn
{
    Header = "Description",
    Binding = CompiledBinding.Create<OperatorActivityRow, string>(static row => row.Description),
});

return table.Columns.Count == 2 &&
       table.ItemsSource is ObservableCollection<OperatorActivityRow> { Count: 1 }
    ? 0
    : 1;

internal sealed record OperatorActivityRow(string Event, string Description);
