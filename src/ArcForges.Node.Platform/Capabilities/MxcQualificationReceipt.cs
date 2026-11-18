// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Node.Platform.Capabilities;

internal static class MxcQualificationReceipt
{
    internal static byte[] Read(string profileId)
    {
        if (profileId is not (MxcProfileAdmission.WindowsProfileId or MxcProfileAdmission.LinuxProfileId))
        {
            return [];
        }

        using var receipt = typeof(MxcQualificationReceipt).Assembly.GetManifestResourceStream(
            "ArcForges.Mxc." + profileId + ".qualification.json");
        if (receipt is null || receipt.Length is <= 0 or > 65_536)
        {
            return [];
        }

        var bytes = new byte[checked((int)receipt.Length)];
        receipt.ReadExactly(bytes);
        return bytes;
    }
}
