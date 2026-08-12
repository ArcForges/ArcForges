// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcChat.Mobile;

public sealed class ArcChatApplication : Microsoft.Maui.Controls.Application
{
    protected override Microsoft.Maui.Controls.Window CreateWindow(Microsoft.Maui.IActivationState? activationState)
    {
        return new Microsoft.Maui.Controls.Window(new Microsoft.Maui.Controls.ContentPage
        {
            Title = "ArcChat Mobile",
            Content = new Microsoft.Maui.Controls.Label
            {
                Text = "Hello from ArcChat Mobile",
                HorizontalOptions = Microsoft.Maui.Controls.LayoutOptions.Center,
                VerticalOptions = Microsoft.Maui.Controls.LayoutOptions.Center
            }
        });
    }
}
