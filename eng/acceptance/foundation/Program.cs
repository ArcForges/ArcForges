// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Application.Abstractions;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Foundation.Execution;
using Google.Protobuf;
using FoundationRevision = ArcForges.Foundation.Revision;
using WireInstant = ArcForges.Contracts.Foundation.V1.Instant;

namespace ArcForges.Acceptance.Foundation;

internal static class Program
{
    private static readonly Guid SampleId = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");

    private static void Main(string[] args)
    {
        if (args.Length != 2 || args[0] is not ("emit" or "verify"))
        {
            throw new ArgumentException("Usage: emit|verify <exchange-directory>");
        }

        string directory = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(directory);
        if (args[0] == "emit")
        {
            Emit(directory);
        }
        else
        {
            Verify(directory);
        }

        Console.WriteLine("Published C# consumer: " + args[0] + " passed.");
    }

    private static void Emit(string directory)
    {
        var command = new CommandId(SampleId);
        var identity = new ExecutionIdentity(ExecutionOwner.ForTask(TaskId.New()), command,
            InvocationId.New(), RunId.New(), StepId.New(), AttemptId.New());
        IExecutionContext context = new ConsumerContext(identity);
        var retry = context.Identity.Retry(EffectCertainty.DidNotHappen, RetryMode.SameCommand);
        Require(identity.Command == retry.Command && identity.Attempt != retry.Attempt, "retry identity");
        Refuses<InvalidOperationException>(() => identity.Retry(EffectCertainty.Unknown, RetryMode.SameCommand));
        Refuses<InvalidOperationException>(() => identity.Retry((EffectCertainty)999, RetryMode.SameCommand));
        Write(directory, "command", identity.Command.ToWire());
        Write(directory, "duplicate-command", retry.Command.ToWire());
        Write(directory, "attempt", identity.Attempt.ToWire());
        Write(directory, "retry-attempt", retry.Attempt.ToWire());
        Write(directory, "revision", new FoundationRevision(SampleId, new CloudRevision(9_007_199_254_740_993L)).ToWire());
        Write(directory, "uint64", new NativeContentRev { Value = ulong.MaxValue });
        Write(directory, "decimal", new ExactDecimal("9007199254740993.000000001").ToWire());
        Write(directory, "rational", new RationalValue(9_007_199_254_740_993L, 2).ToWire());
        Write(directory, "cursor", new PageRequest { Cursor = new OpaqueCursor("opaque/\u03bb?=cursor").ToWire() });
        Write(directory, "absent-instant", new WireInstant());
        Write(directory, "epoch", WireValues.ToWire(default(ArcForges.Foundation.Instant)));
        Write(directory, "unknown-effect", new ArcError { Code = "future.owner.failure", Effect = (EffectCertainty)999,
            Retry = new RetryAdvice { Mode = RetryMode.SameCommand } });
        Write(directory, "unknown-outcome", new ArcError { Code = "internal.unexpected", Category = ErrorCategory.Internal,
            Effect = EffectCertainty.Unknown, Retry = new RetryAdvice { Mode = RetryMode.SameCommand } });
        File.WriteAllBytes(Path.Combine(directory, "unknown-field.bin"), [0xA0, 0x06, 0x01]);
        foreach (var reason in ReasonCodes.All)
        {
            Write(directory, "reason-" + reason.Code, TypedFailure.Create(reason.Code).ToWire());
        }
    }

    private static void Verify(string directory)
    {
        byte[] Read(string name) => File.ReadAllBytes(Path.Combine(directory, name + ".bin"));
        Require(CommandId.FromWire(Id.Parser.ParseFrom(Read("command"))).Value == SampleId, "UUID network order");
        Require(Read("command").SequenceEqual(Read("duplicate-command")), "duplicate logical command");
        Require(!Read("attempt").SequenceEqual(Read("retry-attempt")), "new retry attempt");
        Require(FoundationRevision.FromWire(SampleId, ArcForges.Contracts.Foundation.V1.Revision.Parser.ParseFrom(Read("revision"))).Value.Value == 9_007_199_254_740_993L, "int64 exactness");
        Require(NativeContentRev.Parser.ParseFrom(Read("uint64")).Value == ulong.MaxValue, "uint64 exactness");
        Require(ArcForges.Contracts.Foundation.V1.Decimal.Parser.ParseFrom(Read("decimal")).Value == "9007199254740993.000000001", "decimal exactness");
        Require(RationalValue.FromWire(Rational.Parser.ParseFrom(Read("rational"))) == new RationalValue(9_007_199_254_740_993L, 2), "rational exactness");
        Require(PageRequest.Parser.ParseFrom(Read("cursor")).Cursor == "opaque/\u03bb?=cursor", "opaque cursor");
        Refuses<ArgumentException>(() => WireValues.ReadInstant(WireInstant.Parser.ParseFrom(Read("absent-instant"))));
        Require(WireValues.ReadInstant(WireInstant.Parser.ParseFrom(Read("epoch"))) == default, "explicit epoch");
        var unknown = ArcError.Parser.ParseFrom(Read("unknown-effect"));
        Require((int)unknown.Effect == 999, "unknown enum transport");
        Refuses<InvalidOperationException>(() => new EnumProjection<EffectCertainty>(unknown.Effect).RequireKnown());
        var failure = TypedFailure.FromWire(unknown);
        Require(!failure.IsKnownCode && failure.Effect == EffectCertainty.Unknown && failure.Retry == RetryMode.Never, "unknown reader refusal");
        Refuses<InvalidOperationException>(() => failure.ToWire());
        var uncertain = TypedFailure.FromWire(ArcError.Parser.ParseFrom(Read("unknown-outcome")));
        Require(uncertain.Effect == EffectCertainty.Unknown && uncertain.Retry == RetryMode.Never, "uncertain effect cannot retry automatically");
        Require(Id.Parser.ParseFrom(Read("unknown-field")).ToByteArray().SequenceEqual(new byte[] { 0xA0, 0x06, 0x01 }), "unknown field preservation");
        foreach (var reason in ReasonCodes.All)
        {
            var restored = TypedFailure.FromWire(ArcError.Parser.ParseFrom(Read("reason-" + reason.Code)));
            Require(restored.IsKnownCode && restored.Code == reason.Code && restored.Category == reason.Category && restored.Retry == RetryMode.Never, "registered error " + reason.Code);
        }

        // These values originate in TypeScript, not the C# emitter.
        Require(ArcForges.Contracts.Foundation.V1.Revision.Parser.ParseFrom(Read("ts-revision")).Value == long.MaxValue, "TS to C# int64 max");
        Require(NativeContentRev.Parser.ParseFrom(Read("ts-uint64")).Value == ulong.MaxValue, "TS to C# uint64 max");
        Require(ArcForges.Contracts.Foundation.V1.Decimal.Parser.ParseFrom(Read("ts-decimal")).Value == "-0.000000001", "TS to C# decimal");
        Require(!WireInstant.Parser.ParseFrom(Read("ts-absent-instant")).HasUnixSeconds, "TS absent scalar");
        Require(WireInstant.Parser.ParseFrom(Read("ts-epoch")).HasUnixSeconds, "TS explicit zero");
        Console.WriteLine("Verified " + ReasonCodes.All.Count.ToString(CultureInfo.InvariantCulture) + " registered errors; durable effects are outside this fixture.");
    }

    private static void Write(string directory, string name, IMessage message) =>
        File.WriteAllBytes(Path.Combine(directory, name + ".bin"), message.ToByteArray());

    private static void Require(bool condition, string scenario)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Acceptance failed: " + scenario);
        }
    }

    private static void Refuses<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { return; }
        throw new InvalidOperationException("Expected refusal: " + typeof(T).Name);
    }

    private sealed class ConsumerContext(ExecutionIdentity identity) : IExecutionContext
    {
        public ExecutionIdentity Identity { get; } = identity;
        public IClock Clock => ArcForges.Foundation.Clock.System;
        public CancellationToken Cancellation => CancellationToken.None;
    }
}
