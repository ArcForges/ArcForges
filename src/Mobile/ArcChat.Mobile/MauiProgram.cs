// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcChat.Mobile;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder.UseMauiApp<ArcChatApplication>();
        return builder.Build();
    }
}
