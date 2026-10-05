// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using ArcForges.Native.Abstractions;
using ArcForges.Native.Pdf;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>What a scripted native document does when it is asked for text or a tile.</summary>
internal enum ScriptedRender
{
    Normal,
    ThrowNative,
    SpinUntilCancelled,
    HangIgnoringCancellation,
    ReportsMoreThanItWrote,
    ReportsMoreThanTheDestination,
    FailsAfterWriting,
}

/// <summary>
/// TEST ONLY. A scripted stand-in for the native PDF document, below the production adapter (<see cref="NativePdfParser"/>). It parses no
/// real PDF; it exists so the adapter's limits, validation, paging, cancellation and failure mapping can be driven with hostile answers.
/// </summary>
internal sealed class ScriptedPdfDocument : IPdfDocument
{
    internal List<(PdfPageGeometry Geometry, string Text, PdfTextBox[] Boxes)> Pages { get; } = [];

    internal ScriptedRender RenderBehaviour { get; set; }

    internal Func<uint, uint, PdfTextChunk?>? TextOverride { get; set; }

    internal int RenderCalls { get; private set; }

    internal int TextCalls { get; private set; }

    internal int Disposed { get; private set; }

    internal (uint X, uint Y, uint W, uint H, uint FullW, uint FullH, uint Stride)? LastTile { get; private set; }

    internal ManualResetEventSlim Release { get; } = new(false);

    public uint PageCount => (uint)Pages.Count;

    internal static ScriptedPdfDocument OnePage(string text = "hello world", params PdfTextBox[] boxes)
    {
        var document = new ScriptedPdfDocument();
        document.Pages.Add((new PdfPageGeometry(0, 0, 612, 792), text, boxes));
        return document;
    }

    public PdfPageGeometry GetPage(uint pageIndex)
    {
        if (pageIndex >= Pages.Count)
        {
            throw new PdfNativeException(NativeStatus.NotFound, "no such page");
        }

        return Pages[(int)pageIndex].Geometry;
    }

    public PdfTextChunk ExtractText(uint pageIndex, uint start, uint count, CancellationToken cancellation)
    {
        TextCalls++;
        cancellation.ThrowIfCancellationRequested();
        if (TextOverride?.Invoke(pageIndex, start) is { } forced)
        {
            return forced;
        }

        var page = Pages[(int)pageIndex];
        var end = (int)Math.Min(page.Text.Length, (long)start + count);
        if (end < page.Text.Length && end > start && char.IsLowSurrogate(page.Text[end]) && char.IsHighSurrogate(page.Text[end - 1]))
        {
            end--;
        }

        var boxes = page.Boxes.Where(box => box.Start >= start && (ulong)box.Start + box.Length <= (ulong)end).ToList();
        return new PdfTextChunk(pageIndex, start, end < page.Text.Length ? (uint)end : null, page.Text[(int)start..end], boxes);
    }

    public int Render(PdfPageGeometry page, uint x, uint y, uint width, uint height, uint fullWidth, uint fullHeight, uint rowStride, Span<byte> destination, CancellationToken cancellation)
    {
        RenderCalls++;
        LastTile = (x, y, width, height, fullWidth, fullHeight, rowStride);
        switch (RenderBehaviour)
        {
            case ScriptedRender.ThrowNative:
                throw new PdfNativeException(NativeStatus.Corrupt, "the page is corrupt");
            case ScriptedRender.SpinUntilCancelled:
                while (true)
                {
                    cancellation.ThrowIfCancellationRequested();
                    Thread.Sleep(1);
                }

            case ScriptedRender.HangIgnoringCancellation:
                _ = Release.Wait(TimeSpan.FromSeconds(60), CancellationToken.None);
                return 0;
        }

        var required = ((int)(height - 1) * (int)rowStride) + ((int)width * 4);
        for (var row = 0; row < height; row++)
        {
            for (var column = 0; column < width; column++)
            {
                var offset = (row * (int)rowStride) + (column * 4);
                destination[offset] = (byte)((x + column) & 255);
                destination[offset + 1] = (byte)((y + row) & 255);
                destination[offset + 2] = (byte)(page.PageIndex & 255);
                destination[offset + 3] = 255;
            }
        }

        return RenderBehaviour switch
        {
            ScriptedRender.ReportsMoreThanItWrote => required + 64,
            ScriptedRender.ReportsMoreThanTheDestination => destination.Length + 1,
            ScriptedRender.FailsAfterWriting => throw new PdfNativeException(NativeStatus.Internal, "failed after writing"),
            _ => required,
        };
    }

    public void Dispose() => Disposed++;
}

/// <summary>The strict reader of the native text encoding.</summary>
public sealed class PdfTextJsonTests
{
    private static PdfTextChunk Parse(string json, uint page = 0, uint start = 0) => PdfTextJson.Parse(Encoding.UTF8.GetBytes(json), page, start);

    private const string Golden = "{\"version\":1,\"page\":0,\"start\":0,\"next\":5,\"text\":\"hello\",\"boxes\":[{\"start\":0,\"length\":5,\"x\":1,\"y\":2,\"width\":3,\"height\":4}]}";

    [Fact]
    public void TheEncodingTheNativeEngineWritesIsRead()
    {
        var chunk = Parse(Golden);
        Assert.Equal("hello", chunk.Text);
        Assert.Equal(5u, chunk.Next);
        Assert.Equal(new PdfTextBox(0, 5, 1, 2, 3, 4), Assert.Single(chunk.Boxes));

        var last = Parse("{\"version\":1,\"page\":2,\"start\":5,\"text\":\"\\ud83d\\ude00\\u000a\",\"boxes\":[]}", 2, 5);
        Assert.Equal("\U0001F600\n", last.Text);
        Assert.Null(last.Next);
    }

    [Theory]
    [InlineData("{\"version\":2,\"page\":0,\"start\":0,\"text\":\"\",\"boxes\":[]}")]
    [InlineData("{\"version\":1,\"page\":1,\"start\":0,\"text\":\"\",\"boxes\":[]}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":3,\"text\":\"\",\"boxes\":[]}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"boxes\":[]}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"text\":\"\"}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"text\":\"\",\"boxes\":[],\"extra\":1}")]
    [InlineData("{\"version\":1,\"version\":1,\"page\":0,\"start\":0,\"text\":\"\",\"boxes\":[]}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"next\":0,\"text\":\"ab\",\"boxes\":[]}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"next\":9,\"text\":\"ab\",\"boxes\":[]}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"text\":\"ab\",\"boxes\":[{\"start\":1,\"length\":5,\"x\":0,\"y\":0,\"width\":1,\"height\":1}]}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"text\":\"ab\",\"boxes\":[{\"start\":0,\"length\":0,\"x\":0,\"y\":0,\"width\":1,\"height\":1}]}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"text\":\"ab\",\"boxes\":[{\"start\":0,\"length\":1,\"x\":0,\"y\":0,\"width\":-1,\"height\":1}]}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"text\":\"ab\",\"boxes\":[{\"start\":0,\"length\":1,\"x\":1e999,\"y\":0,\"width\":1,\"height\":1}]}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"text\":\"ab\",\"boxes\":[{\"start\":0,\"length\":1,\"x\":0,\"y\":0,\"width\":1}]}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"text\":7,\"boxes\":[]}")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"text\":\"\",\"boxes\":{}}")]
    [InlineData("[]")]
    [InlineData("")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"text\":\"\",\"boxes\":[]} trailing")]
    [InlineData("{\"version\":1,\"page\":0,\"start\":0,\"text\":\"\",\"boxes\":[],}")]
    public void AnythingElseRefusesTheWholeChunk(string json) =>
        _ = Assert.Throws<PdfNativeException>(() => Parse(json));

    [Fact]
    public void ABoxBeforeTheChunkIsRefused() =>
        _ = Assert.Throws<PdfNativeException>(() => Parse("{\"version\":1,\"page\":0,\"start\":4,\"text\":\"ab\",\"boxes\":[{\"start\":3,\"length\":1,\"x\":0,\"y\":0,\"width\":1,\"height\":1}]}", 0, 4));
}

/// <summary>The production PDF adapter driven with hostile answers of the native side.</summary>
public sealed class NativePdfParserTests
{
    private static readonly ContentSandboxLimits Limits = new() { TimeoutMs = 5000, MaxWidth = 4096, MaxHeight = 4096 };

    private static ParserContext Context() => new(Limits, Xunit.TestContext.Current.CancellationToken);

    private static ParserContext ContextWith(CancellationToken cancelled) => new(Limits, cancelled);

    private static ParserInput Input() => new(new Mapping(new byte[16]), 16);

    private static NativePdfParser Parser(ScriptedPdfDocument document, Action<PdfLimits>? seen = null) =>
        new((_, limits, _) =>
        {
            seen?.Invoke(limits);
            return document;
        });

    private sealed class Mapping(byte[] bytes) : ArcForges.LocalRpc.ILocalRpcBufferMapping
    {
        public long Length => bytes.Length;

        public int Read(long offset, Span<byte> destination)
        {
            var count = (int)Math.Min(destination.Length, bytes.Length - offset);
            bytes.AsSpan((int)offset, count).CopyTo(destination);
            return count;
        }

        public void Dispose()
        {
        }
    }

    [Fact]
    public void OpenPassesTheLaunchBudgetToTheNativeLibraryAndReturnsThePageCount()
    {
        PdfLimits? seen = null;
        using var parser = Parser(ScriptedPdfDocument.OnePage(), limits => seen = limits);
        Assert.Equal(1u, parser.Open(Input(), Context()));
        Assert.Equal(new PdfLimits(Limits.MaxInputBytes, Limits.MaxMemoryBytes, Limits.MaxOutputBytes, 4096, 4096, Limits.MaxItems, 5000), seen);
        _ = Assert.Throws<ContentParserException>(() => parser.Open(Input(), Context()));
    }

    [Fact]
    public void ADocumentWithoutPagesIsRefusedAndReleased()
    {
        var empty = new ScriptedPdfDocument();
        using var parser = Parser(empty);
        _ = Assert.Throws<ContentParserException>(() => parser.Open(Input(), Context()));
        Assert.Equal(1, empty.Disposed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public void EveryNativeOrLoaderFailureIsOneParserFailure(int which)
    {
        Exception failure = which switch
        {
            0 => new PdfNativeException(NativeStatus.Corrupt, "bad"),
            1 => new DllNotFoundException(),
            2 => new EntryPointNotFoundException(),
            3 => new BadImageFormatException(),
            4 => new PlatformNotSupportedException(),
            5 => new InvalidDataException(),
            6 => new FileNotFoundException(),
            _ => new InvalidOperationException(),
        };
        using var parser = new NativePdfParser((_, _, _) => throw failure);
        _ = Assert.Throws<ContentParserException>(() => parser.Open(Input(), Context()));
    }

    [Fact]
    public void ACancellationIsNotAParserFailure()
    {
        using var source = new CancellationTokenSource();
        using var parser = new NativePdfParser((_, _, token) =>
        {
            source.Cancel();
            token.ThrowIfCancellationRequested();
            return ScriptedPdfDocument.OnePage();
        });
        _ = Assert.ThrowsAny<OperationCanceledException>(() => parser.Open(Input(), ContextWith(source.Token)));
    }

    [Theory]
    [InlineData(double.NaN, 792.0, 0u)]
    [InlineData(612.0, double.PositiveInfinity, 0u)]
    [InlineData(0.0, 792.0, 0u)]
    [InlineData(612.0, -1.0, 0u)]
    [InlineData(612.0, 792.0, 45u)]
    public void APageWithImpossibleGeometryIsRefused(double width, double height, uint rotation)
    {
        var document = new ScriptedPdfDocument();
        document.Pages.Add((new PdfPageGeometry(0, rotation, width, height), "x", []));
        using var parser = Parser(document);
        _ = parser.Open(Input(), Context());
        _ = Assert.Throws<ContentParserException>(() => parser.GetPage(0, Context()));
    }

    [Fact]
    public void APageTheNativeLibraryDoesNotHaveIsAParserFailure()
    {
        using var parser = Parser(ScriptedPdfDocument.OnePage());
        _ = parser.Open(Input(), Context());
        var page = parser.GetPage(0, Context());
        Assert.Equal((0u, 0u, 612d, 792d), (page.PageIndex, page.Rotation, page.WidthPoints, page.HeightPoints));
        _ = Assert.Throws<ContentParserException>(() => parser.GetPage(5, Context()));
    }

    [Fact]
    public void LongPageTextIsAssembledFromBoundedNativeChunksWithAbsoluteBoxes()
    {
        var text = string.Concat(Enumerable.Repeat("word \U0001F600 ", 30000)); // 240000 UTF-16 units: four native chunks
        var boxes = new List<PdfTextBox>();
        for (uint position = 0; position + 4 <= text.Length; position += 9)
        {
            boxes.Add(new PdfTextBox(position, 4, position, 0, 4, 10));
        }

        var document = ScriptedPdfDocument.OnePage(text, [.. boxes]);
        using var parser = Parser(document);
        _ = parser.Open(Input(), Context());
        var page = parser.GetPageText(0, Context());
        Assert.Equal(text, page.Text);
        Assert.True(document.TextCalls >= 4);
        // A box that crosses a chunk end is not carried by either chunk (the native rule); every other box arrives once, at its absolute offset.
        var expected = boxes.Select(box => (box.Start, box.Length)).ToHashSet();
        Assert.All(page.Boxes, box => Assert.Contains((box.Start, box.Length), expected));
        Assert.InRange(page.Boxes.Count, boxes.Count - document.TextCalls, boxes.Count);
        Assert.Equal(page.Boxes.Count, page.Boxes.Select(box => box.Start).Distinct().Count());
    }

    [Fact]
    public void ATextChunkThatMakesNoProgressOrAnswersAnotherPositionIsRefused()
    {
        var document = ScriptedPdfDocument.OnePage("abcdef");
        document.TextOverride = (page, start) => start == 0 ? new PdfTextChunk(page, 0, 3, "abc", []) : new PdfTextChunk(page, 3, 3, "def", []);
        using var parser = Parser(document);
        _ = parser.Open(Input(), Context());
        _ = Assert.Throws<ContentParserException>(() => parser.GetPageText(0, Context()));

        document.TextOverride = (page, start) => new PdfTextChunk(page, start + 1, null, "x", []);
        _ = Assert.Throws<ContentParserException>(() => parser.GetPageText(0, Context()));

        document.TextOverride = (page, start) => new PdfTextChunk(page, start, start + 10, "abc", []);
        _ = Assert.Throws<ContentParserException>(() => parser.GetPageText(0, Context()));
    }

    [Fact]
    public void ATextVolumeOrBoxCountBeyondTheBoundIsRefused()
    {
        var huge = new string('x', 65536);
        var document = ScriptedPdfDocument.OnePage("a");
        document.TextOverride = (page, start) => new PdfTextChunk(page, start, start + (uint)huge.Length, huge, []);
        using var parser = Parser(document);
        _ = parser.Open(Input(), Context());
        _ = Assert.Throws<ContentParserException>(() => parser.GetPageText(0, Context()));

        var boxes = Enumerable.Range(0, 500_000).Select(_ => new PdfTextBox(0, 1, 0, 0, 1, 1)).ToList();
        var crowded = ScriptedPdfDocument.OnePage("a");
        var round = 0;
        crowded.TextOverride = (page, start) => ++round > 3 ? throw new InvalidOperationException("must have stopped") : new PdfTextChunk(page, start, start + 1, "a", boxes);
        using var crowdedParser = Parser(crowded);
        _ = crowdedParser.Open(Input(), Context());
        _ = Assert.Throws<ContentParserException>(() => crowdedParser.GetPageText(0, Context()));
    }

    [Fact]
    public void TextExtractionStopsBetweenChunksWhenCancelled()
    {
        using var source = new CancellationTokenSource();
        var document = ScriptedPdfDocument.OnePage(new string('y', 200000));
        using var parser = Parser(document);
        _ = parser.Open(Input(), ContextWith(source.Token));
        document.TextOverride = (page, start) =>
        {
            source.Cancel();
            return new PdfTextChunk(page, start, start + 1, "y", []);
        };
        _ = Assert.ThrowsAny<OperationCanceledException>(() => parser.GetPageText(0, ContextWith(source.Token)));
        Assert.Equal(1, document.TextCalls);
    }

    [Fact]
    public void ATileIsRenderedWithTheRegionTheStrideAndTheGridOfTheRequest()
    {
        var document = ScriptedPdfDocument.OnePage();
        using var parser = Parser(document);
        _ = parser.Open(Input(), Context());
        var page = parser.GetPage(0, Context());
        var region = new SandboxRegion { X = 8, Y = 4, Width = 3, Height = 2, RowStride = 20 };
        var destination = new byte[4096];
        var written = parser.RenderTile(page, region, 100, 200, destination, Context());
        Assert.Equal(32, written);
        Assert.Equal((8u, 4u, 3u, 2u, 100u, 200u, 20u), document.LastTile);
        Assert.Equal(new byte[] { 8, 4, 0, 255 }, destination[..4]);
        Assert.Equal(new byte[] { 8, 5, 0, 255 }, destination[20..24]);
    }

    [Theory]
    [InlineData((int)ScriptedRender.ThrowNative)]
    [InlineData((int)ScriptedRender.ReportsMoreThanTheDestination)]
    [InlineData((int)ScriptedRender.FailsAfterWriting)]
    public void ARenderThatFailsOrOverclaimsIsOneParserFailure(int behaviour)
    {
        var document = ScriptedPdfDocument.OnePage();
        document.RenderBehaviour = (ScriptedRender)behaviour;
        using var parser = Parser(document);
        _ = parser.Open(Input(), Context());
        var page = parser.GetPage(0, Context());
        var region = new SandboxRegion { X = 0, Y = 0, Width = 4, Height = 4, RowStride = 16 };
        _ = Assert.Throws<ContentParserException>(() => parser.RenderTile(page, region, 64, 64, new byte[4096], Context()));
    }

    [Fact]
    public void AStrideBeyondTheNativeRangeIsRefusedBeforeTheNativeCall()
    {
        var document = ScriptedPdfDocument.OnePage();
        using var parser = Parser(document);
        _ = parser.Open(Input(), Context());
        var page = parser.GetPage(0, Context());
        var region = new SandboxRegion { X = 0, Y = 0, Width = 4, Height = 4, RowStride = (ulong)uint.MaxValue + 1 };
        _ = Assert.Throws<ContentParserException>(() => parser.RenderTile(page, region, 64, 64, new byte[4096], Context()));
        Assert.Equal(0, document.RenderCalls);
    }

    [Fact]
    public void ARenderIsCancelledThroughTheTokenAndDisposeReleasesTheDocumentOnce()
    {
        using var source = new CancellationTokenSource();
        var document = ScriptedPdfDocument.OnePage();
        document.RenderBehaviour = ScriptedRender.SpinUntilCancelled;
        var parser = Parser(document);
        _ = parser.Open(Input(), Context());
        var page = parser.GetPage(0, Context());
        var region = new SandboxRegion { X = 0, Y = 0, Width = 4, Height = 4, RowStride = 16 };
        source.CancelAfter(50);
        _ = Assert.ThrowsAny<OperationCanceledException>(() => parser.RenderTile(page, region, 64, 64, new byte[4096], ContextWith(source.Token)));
        parser.Dispose();
        parser.Dispose();
        Assert.Equal(1, document.Disposed);
        _ = Assert.Throws<ContentParserException>(() => parser.GetPage(0, Context()));
    }
}

/// <summary>The production composition: what it contains, what it refuses and how it is prepared.</summary>
public sealed class ProductionCompositionTests
{
    [Fact]
    public void TheProductionHelperComposesTheProductionParsersOnlyAndNeverTheHostileTestParser()
    {
        var production = ParserProfiles.Production;
        var composed = Assert.IsType<ProductionParserProfile>(production.Find(ProductionParserProfile.ProfileId));
        Assert.Null(composed.CreateImageParser());
        using var pdf = composed.CreatePdfParser();
        Assert.NotNull(pdf);
        Assert.Null(production.Find(HostileFixture.HostileProfile.ProfileId));
        Assert.Null(production.Find("none"));
    }

    [Fact]
    public void PreparationFailsClosedWhenTheNativeLibraryCannotBeLoaded()
    {
        // This test host has no ArcPdfNative next to it (and no manifest): the production preparation must refuse, not defer to the first call.
        var profile = new ProductionParserProfile();
        _ = Assert.Throws<ContentParserException>(profile.Prepare);
    }

    [Fact]
    public void ACompositionPreparesBeforeAnyParserExists()
    {
        var prepared = 0;
        var profile = new ProductionParserProfile(prepare: () => prepared++);
        profile.Prepare();
        Assert.Equal(1, prepared);
    }

    [Fact]
    public async Task APdfOpensPagesExtractsAndRendersEndToEndThroughTheRealHostAndBroker()
    {
        var document = ScriptedPdfDocument.OnePage("first page");
        document.Pages.Add((new PdfPageGeometry(1, 90, 300, 400), new string('z', 70000), []));
        var launcher = new InProcessHelperLauncher(new ParserProfiles([new ProductionParserProfile((_, _, _) => document, () => { })]));
        var (sandbox, _, invocation) = await Fixtures.LaunchAsync(new byte[] { 1, 2, 3, 4 }, Fixtures.Options(parser: ProductionParserProfile.ProfileId), launcher);
        await using var _l = sandbox;
        await using var _i = invocation;
        var ct = Xunit.TestContext.Current.CancellationToken;

        var opened = await invocation.OpenPdfAsync(ct);
        Assert.True(opened.IsSuccess, opened.Failure?.Code);
        var first = (await invocation.GetPdfPageAsync(opened.Value, 0, ct)).Value!;
        Assert.Equal((612d, 792d), (first.WidthPoints, first.HeightPoints));
        var second = (await invocation.GetPdfPageAsync(opened.Value, 1, ct)).Value!;
        Assert.Equal(90u, second.Rotation);

        var text = (await invocation.ExtractPdfTextAsync(opened.Value, 0, 0, ct)).Value!;
        Assert.Equal("first page", text.Text);
        var total = 0;
        uint start = 0;
        while (true)
        {
            var chunk = (await invocation.ExtractPdfTextAsync(opened.Value, 1, start, ct)).Value!;
            total += chunk.Text.Length;
            if (!chunk.HasNext)
            {
                break;
            }

            start = chunk.Next;
        }

        Assert.Equal(70000, total);
        using var tile = (await invocation.RenderPdfTileAsync(opened.Value, first, 600, 780, 8, 8, 16, 8, ct)).Value!;
        Assert.Equal((16u, 8u), (tile.Width, tile.Height));
        Assert.Equal((8u, 8u, 16u, 8u, 600u, 780u), (document.LastTile!.Value.X, document.LastTile.Value.Y, document.LastTile.Value.W, document.LastTile.Value.H, document.LastTile.Value.FullW, document.LastTile.Value.FullH));
        Assert.True((await invocation.ClosePdfAsync(opened.Value, ct)).IsSuccess);
        Assert.Equal(1, document.Disposed);
    }

    [Fact]
    public async Task ARenderBeyondTheDocumentBudgetIsRefusedWithoutTheNativeLibraryBeingCalled()
    {
        var document = ScriptedPdfDocument.OnePage();
        var launcher = new InProcessHelperLauncher(new ParserProfiles([new ProductionParserProfile((_, _, _) => document, () => { })]));
        var (sandbox, _, invocation) = await Fixtures.LaunchAsync(new byte[] { 1, 2, 3, 4 }, Fixtures.Options(parser: ProductionParserProfile.ProfileId), launcher);
        await using var _l = sandbox;
        await using var _i = invocation;
        var ct = Xunit.TestContext.Current.CancellationToken;
        var opened = (await invocation.OpenPdfAsync(ct)).Value;
        var page = (await invocation.GetPdfPageAsync(opened, 0, ct)).Value!;
        var tooWide = await invocation.RenderPdfTileAsync(opened, page, 5000, 100, 0, 0, 8, 8, ct);
        Assert.False(tooWide.IsSuccess);
        var outside = await invocation.RenderPdfTileAsync(opened, page, 100, 100, 96, 0, 8, 8, ct);
        Assert.False(outside.IsSuccess);
        Assert.Equal(0, document.RenderCalls);
    }

    [Fact]
    public async Task AnOpenThatFailsInTheNativeLibraryIsOneParserFailureAndTheParentCarriesOn()
    {
        var launcher = new InProcessHelperLauncher(new ParserProfiles([new ProductionParserProfile((_, _, _) => throw new PdfNativeException(NativeStatus.Corrupt, "not a pdf"), () => { })]));
        var (sandbox, _, invocation) = await Fixtures.LaunchAsync(new byte[] { 1, 2, 3, 4 }, Fixtures.Options(parser: ProductionParserProfile.ProfileId), launcher);
        await using var _l = sandbox;
        await using var _i = invocation;
        var opened = await invocation.OpenPdfAsync(Xunit.TestContext.Current.CancellationToken);
        Assert.False(opened.IsSuccess);
        Assert.Equal("resource.parser_failed", opened.Failure!.Code);
    }

    [Fact]
    public async Task AnImageAgainstTheProductionCompositionIsRefusedBecauseNoImageParserIsComposed()
    {
        var launcher = new InProcessHelperLauncher(new ParserProfiles([new ProductionParserProfile((_, _, _) => ScriptedPdfDocument.OnePage(), () => { })]));
        var (sandbox, _, invocation) = await Fixtures.LaunchAsync(new byte[] { 1, 2, 3, 4 }, Fixtures.Options(parser: ProductionParserProfile.ProfileId), launcher);
        await using var _l = sandbox;
        await using var _i = invocation;
        var image = await invocation.OpenImageAsync(0, 0, 1, Xunit.TestContext.Current.CancellationToken);
        Assert.False(image.IsSuccess);
    }

    [Fact]
    public async Task ANativeRenderThatNeverReturnsEndsTheHelperAtItsDeadlineAndTheParentCarriesOn()
    {
        var document = ScriptedPdfDocument.OnePage();
        document.RenderBehaviour = ScriptedRender.HangIgnoringCancellation;
        var limits = new ContentSandboxLimits { TimeoutMs = 600, MaxWidth = 4096, MaxHeight = 4096 };
        var launcher = new InProcessHelperLauncher(new ParserProfiles([new ProductionParserProfile((_, _, _) => document, () => { })]));
        var (sandbox, _, invocation) = await Fixtures.LaunchAsync(new byte[] { 1, 2, 3, 4 }, Fixtures.Options(parser: ProductionParserProfile.ProfileId, limits: limits), launcher);
        await using var _l = sandbox;
        await using var _i = invocation;
        var ct = Xunit.TestContext.Current.CancellationToken;
        var opened = (await invocation.OpenPdfAsync(ct)).Value;
        var page = (await invocation.GetPdfPageAsync(opened, 0, ct)).Value!;
        var started = DateTime.UtcNow;
        var tile = await invocation.RenderPdfTileAsync(opened, page, 64, 64, 0, 0, 8, 8, ct);
        Assert.False(tile.IsSuccess);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(20));
        Assert.Equal(ContentSandboxContract.ExitParserHung, await invocation.WaitForExitAsync(ct));
        document.Release.Set();
    }
}
