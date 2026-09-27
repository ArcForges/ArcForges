// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Foundation.Execution;

/// <summary>Exactly one logical execution owner, never an implicit promotion from chat to task.</summary>
public sealed record ExecutionOwner
{
    private ExecutionOwner(TaskId? task, ChatTurnId? chatTurn)
    {
        Task = task;
        ChatTurn = chatTurn;
    }

    public TaskId? Task { get; }
    public ChatTurnId? ChatTurn { get; }
    public static ExecutionOwner ForTask(TaskId task)
    {
        _ = task.ToWire();
        return new(task, null);
    }

    public static ExecutionOwner ForChatTurn(ChatTurnId chatTurn)
    {
        _ = chatTurn.ToWire();
        return new(null, chatTurn);
    }
}

/// <summary>Memory-only command/attempt identity; durable single-effect receipts belong to persistence.</summary>
public sealed record ExecutionIdentity
{
    public ExecutionIdentity(ExecutionOwner owner, CommandId command, InvocationId invocation, RunId run, StepId step, AttemptId attempt)
    {
        ArgumentNullException.ThrowIfNull(owner);
        _ = command.ToWire();
        _ = invocation.ToWire();
        _ = run.ToWire();
        _ = step.ToWire();
        _ = attempt.ToWire();
        Owner = owner;
        Command = command;
        Invocation = invocation;
        Run = run;
        Step = step;
        Attempt = attempt;
    }

    public ExecutionOwner Owner { get; }
    public CommandId Command { get; }
    public InvocationId Invocation { get; }
    public RunId Run { get; }
    public StepId Step { get; }
    public AttemptId Attempt { get; }

    /// <summary>Only a known no-effect or explicitly reconciled attempt may allocate a retry.</summary>
    public ExecutionIdentity Retry(EffectCertainty effect, RetryMode advice, bool reconciliationAuthorized = false)
    {
        var permitted = effect == EffectCertainty.DidNotHappen && advice == RetryMode.SameCommand
            || effect == EffectCertainty.Unknown && advice == RetryMode.Reconcile && reconciliationAuthorized;
        if (!permitted)
        {
            throw new InvalidOperationException("Retry is not authorized by the known effect and advice.");
        }

        return new ExecutionIdentity(Owner, Command, Invocation, Run, Step, AttemptId.New());
    }
}
