// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Tests.DesktopExperienceGallery;

/// <summary>
/// Scope this project owns but has not reached yet. Step 01 creates only the compilable skeleton;
/// the owning step deletes the skip and replaces the body with real assertions.
/// </summary>
public sealed class PendingScopeTests
{
    [Xunit.Fact(Skip = "Owned by Step 06. Unlock when the gallery composes the shared experience surface and publishes an AOT smoke app.")]
    [Xunit.Trait("Category", "Ui")]
    public void GalleryPublishesAnAotSmokeApp() =>
        Xunit.Assert.Fail("Step 06 must replace this placeholder with real assertions before removing the skip.");
}
