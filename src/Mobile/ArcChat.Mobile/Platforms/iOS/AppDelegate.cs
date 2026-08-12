// SPDX-License-Identifier: AGPL-3.0-only

#if IOS
using Foundation;

namespace ArcChat.Mobile;

[Register("AppDelegate")]
public sealed class AppDelegate : Microsoft.Maui.MauiUIApplicationDelegate
{
    protected override Microsoft.Maui.Hosting.MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();
}
#endif
