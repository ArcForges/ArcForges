// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.ContentSandbox.Host;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

public sealed class NativeProductionProfileTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExactHistoricalAndReceiptBoundProfilesParse(bool receiptBound)
    {
        var bytes = Profile(receiptBound);
        Assert.Equal("KERNEL32.dll", Assert.Single(NativeProductionBootstrap.ReadProfile(bytes, "win-x64", "ArcPdfNative", Hash(bytes))));
    }

    [Fact]
    public void AuthenticatedHashMissingUnknownDuplicateAndInvalidReceiptFieldsRefuse()
    {
        var bytes = Profile(true);
        Assert.Throws<InvalidDataException>(() => NativeProductionBootstrap.ReadProfile(bytes, "win-x64", "ArcPdfNative", new string('f', 64)));
        var original = Encoding.UTF8.GetString(bytes);
        foreach (var changed in new[]
        {
            original.Replace("\"schemaVersion\":2", "\"schemaVersion\":3", StringComparison.Ordinal),
            original.Replace("\"schemaVersion\":2", "\"schemaVersion\":2,\"schemaVersion\":2", StringComparison.Ordinal),
            original.Replace("\"familyIndexSha256\":\"" + new string('d', 64) + "\"", "\"foreign\":\"value\"", StringComparison.Ordinal),
            original.Replace(new string('c', 64), "invalid", StringComparison.Ordinal),
            original.Replace("\"KERNEL32.dll\"", "\"KERNEL32.dll\",\"kernel32.dll\"", StringComparison.Ordinal),
            original.Replace("\"KERNEL32.dll\"", "\"*\"", StringComparison.Ordinal),
        })
        {
            var changedBytes = Encoding.UTF8.GetBytes(changed);
            Assert.Throws<InvalidDataException>(() => NativeProductionBootstrap.ReadProfile(changedBytes, "win-x64", "ArcPdfNative", Hash(changedBytes)));
        }
    }

    private static byte[] Profile(bool receiptBound) => Encoding.UTF8.GetBytes(
        "{\"schemaVersion\":" + (receiptBound ? "2" : "1") + ",\"library\":\"ArcPdfNative\",\"rid\":\"win-x64\","
        + "\"producerProfileSha256\":\"" + new string('a', 64) + "\",\"systemPolicySha256\":\"" + new string('b', 64) + "\","
        + (receiptBound ? "\"producerReceiptSha256\":\"" + new string('c', 64) + "\",\"familyIndexSha256\":\"" + new string('d', 64) + "\"," : "")
        + "\"systemImports\":[\"KERNEL32.dll\"]}");

    private static string Hash(byte[] profile) => Convert.ToHexStringLower(SHA256.HashData(profile));
}
