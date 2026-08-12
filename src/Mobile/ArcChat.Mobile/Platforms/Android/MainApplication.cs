// SPDX-License-Identifier: AGPL-3.0-only

using Android.App;
using Android.Runtime;

namespace ArcChat.Mobile;

[Application]
public sealed class MainApplication(nint handle, JniHandleOwnership ownership)
    : Microsoft.Maui.MauiApplication(handle, ownership)
{
    protected override Microsoft.Maui.Hosting.MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();
}
