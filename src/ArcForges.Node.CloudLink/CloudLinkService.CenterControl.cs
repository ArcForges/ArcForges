// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink;

internal sealed partial class CloudLinkService
{
    private static readonly CenterEndpoint OfficialCenter = CenterEndpoint.Parse(CenterEndpoint.OfficialDefault);
    private V2ChannelEnrollment? _v2Enrollment;
    private bool _v2PreviouslyObserved;
    private string _remoteRevocation = "not_requested";

    internal CenterConnection GetCenterStatus()
    {
        var configured = Configured();
        var channel = _channel?.Status;
        var endingFlow = SignIn.CenterCancellationPending;
        lock (_stateLock)
        {
            var enabled = _phase == CloudLinkPhase.SignedIn && _link is { UseV2: true, ChannelDisabled: not true, ConnectionPaused: not true } &&
                configured is not null && configured.Url == _record?.CenterUrl;
            var active = enabled ? _v2Enrollment : null;
            var connection = new CenterConnection
            {
                State = _link is { State: LinkStates.Ending } || (_signingIn && endingFlow) ? "ending" :
                    _warnings.Contains(Warnings.StoreUnavailable) ? "recovery_required" :
                    _signingIn ? "sign_in_pending" : active is not null ? "linked" :
                    _phase == CloudLinkPhase.SignedIn ? "disconnected" : "signed_out",
                ConnectionEnabled = enabled,
                EnrollmentId = active is null ? null : new Id { Value = ByteString.CopyFrom(Convert.FromHexString(active.EnrollmentId)) },
                ChannelState = active is not null ? "online" : !enabled ? "offline" :
                    channel?.State == RelayState.Connecting ? "connecting" : _v2PreviouslyObserved ? "stale" : "offline",
                ObservedAt = ProtoTime.ToInstant(_options.Clock.GetUtcNow()),
                RemoteRevocation = _remoteRevocation,
            };
            if (configured is { Scheme: "https" })
            {
                connection.CenterOrigin = configured.Origin;
                connection.ServiceMode = configured.Url == OfficialCenter.Url ? "official" : "self_hosted";
            }

            connection.ReasonCodes.AddRange(_warnings.Order(StringComparer.Ordinal));
            if (enabled && channel is not null)
            {
                connection.ReasonCodes.Add(channel.V2Reason ?? channel.Reason);
            }

            return connection;
        }
    }

    internal CenterConnectFlow? GetCenterFlow(Id id) => SignIn.ReadCenterFlow(id);

    internal async Task<(Id? FlowId, ArcError? Error)> BeginCenterConnectAsync(string origin, string mode, string flowKind,
        CancellationToken cancellationToken)
    {
        if (!CenterEndpoint.TryParse(origin, out var requested, out _) || requested.Scheme != "https" || requested.Url != requested.Origin ||
            mode is not ("official" or "self_hosted") || (mode == "official") != (requested.Origin == OfficialCenter.Origin) ||
            flowKind is not ("browser" or "device_code"))
        {
            return (null, CenterControlError(ErrorCategory.Validation, "invalid_argument", "center_connect_selection_invalid"));
        }

        Id? flow = null;
        ArcError? error = null;
        using (await EnterAsync(cancellationToken).ConfigureAwait(false))
        {
            var configured = Configured(out var invalid);
            if (invalid || Stopping || SignIn.HasUnsettledFlow)
            {
                return (null, CenterBusy("center_change_unavailable"));
            }

            var selected = mode == "official" ? OfficialCenter : configured?.Origin == requested.Origin ? configured : requested;
            var selectionChanged = selected.Url != configured?.Url;
            if (selectionChanged)
            {
                if (!CanChangeCenter() || _options.ConfigureCenter is not { } configure)
                {
                    return (null, CenterBusy("center_change_requires_disconnection"));
                }

                if (await configure(selected).ConfigureAwait(false) is not null)
                {
                    return (null, CenterBusy("center_configuration_refused"));
                }

                RebindConfiguredCenter();
                SetV2Enrollment(null, resetHistory: true);
            }

            if (Phase == CloudLinkPhase.SignedIn)
            {
                if (!SetCenterConnectionHeld(enabled: true))
                {
                    error = CenterBusy("center_credential_unavailable");
                }
            }
            else
            {
                var signIn = flowKind == "browser" ? SignInMethod.Browser : SignInMethod.DeviceCode;
                (flow, error) = SignIn.StartCenterFlow(signIn);
            }

            if (error is null)
            {
                lock (_stateLock)
                {
                    _remoteRevocation = "not_requested";
                }

                _options.Log.Info("center.control.connect", new LogField("flowReserved", flow is not null));
            }
            else if (selectionChanged)
            {
                _options.Log.Warning("center.control.selection_persisted", new LogField("errorCode", error.Code));
                error = CenterControlError(ErrorCategory.Execution, "outcome_unknown", "center_selection_persisted_flow_unconfirmed",
                    EffectCertainty.Unknown);
            }
        }

        Wake();
        await PublishAsync(null).ConfigureAwait(false);
        return (flow, error);
    }

    internal async Task<ArcError?> CancelCenterConnectAsync(Id flowId, CancellationToken cancellationToken)
    {
        using (await EnterAsync(cancellationToken).ConfigureAwait(false))
        {
            return SignIn.CancelCenterFlow(flowId);
        }
    }

    internal async Task<ArcError?> DisconnectCenterAsync(CancellationToken cancellationToken)
    {
        using (await EnterAsync(cancellationToken).ConfigureAwait(false))
        {
            if (!SetCenterConnectionHeld(enabled: false))
            {
                return CenterBusy("center_credential_unavailable");
            }

            SignIn.CancelActive();
            SetV2Enrollment(null, resetHistory: false);
            _options.Log.Info("center.control.disconnected");
        }

        Wake();
        await PublishAsync(null).ConfigureAwait(false);
        return null;
    }

    internal async Task<(string RemoteRevocation, ArcError? Error)> SignOutCenterAsync(CancellationToken cancellationToken)
    {
        string remote;
        SignOutResult result;
        bool localPending;
        using (await EnterForSignOutAsync(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false))
        {
            if (Phase == CloudLinkPhase.SignedIn && !SetCenterConnectionHeld(enabled: false))
            {
                return ("not_requested", CenterBusy("center_credential_unavailable"));
            }

            SignIn.CancelActive();
            var pending = SignIn.HasUnsettledFlow;
            SetV2Enrollment(null, resetHistory: false);
            // The protected pause is persistent and immediately fences channel authority before the bounded remote request.
            _channel?.LinkChanged();
            result = await SignOutHeldAsync(revokeRemote: true, TimeSpan.FromSeconds(4)).ConfigureAwait(false);
            lock (_stateLock)
            {
                localPending = _link?.State == LinkStates.Ending || _warnings.Contains(Warnings.StoreUnavailable);
                remote = pending || result == SignOutResult.RemoteUnconfirmed ? "unknown" :
                    result == SignOutResult.RemoteConfirmed ? "confirmed" : _remoteRevocation;
                _remoteRevocation = remote;
            }
        }

        Wake();
        await PublishCurrentAsync().ConfigureAwait(false);
        return (remote, localPending || result == SignOutResult.StoreUnavailable
            ? CenterControlError(ErrorCategory.Execution, "outcome_unknown", "center_local_credential_end_unconfirmed", EffectCertainty.Unknown)
            : null);
    }

    V2ChannelSnapshot? IChannelHost.V2Snapshot() => _options.V2Snapshot?.Invoke();

    void IChannelHost.V2EnrollmentChanged(V2ChannelEnrollment? enrollment) => SetV2Enrollment(enrollment, resetHistory: false);

    private void SetV2Enrollment(V2ChannelEnrollment? enrollment, bool resetHistory)
    {
        lock (_stateLock)
        {
            if (enrollment is not null && (_phase != CloudLinkPhase.SignedIn ||
                _link is not { UseV2: true, ChannelDisabled: not true, ConnectionPaused: not true } ||
                _record is not { } record || record.CenterUrl != enrollment.Center.Url || record.AccountId != enrollment.AccountId ||
                record.InstallationId != enrollment.LinkedInstallationId))
            {
                return;
            }

            _v2PreviouslyObserved = !resetHistory && (_v2PreviouslyObserved || enrollment is not null);
            if (_v2Enrollment == enrollment)
            {
                return;
            }

            _v2Enrollment = enrollment;
            _options.V2EnrollmentChanged?.Invoke(enrollment);
        }
    }

    private bool CanChangeCenter()
    {
        lock (_stateLock)
        {
            return _link?.State != LinkStates.Ending && !_pendingWrite && _ambiguousToken is null &&
                !_warnings.Contains(Warnings.StoreUnavailable) && (_link is null || Unowned(_link) is null) &&
                (_phase != CloudLinkPhase.SignedIn || _link?.ChannelDisabled == true);
        }
    }

    private bool IsCenterPaused()
    {
        lock (_stateLock)
        {
            return _link?.ConnectionPaused == true;
        }
    }

    private static ArcError CenterBusy(string reason) => CenterControlError(ErrorCategory.State, "busy", reason);

    internal static ArcError CenterControlError(ErrorCategory category, string code, string reason, EffectCertainty effect = EffectCertainty.DidNotHappen) => new()
    {
        Category = category,
        Code = code,
        MessageKey = "center." + code,
        Effect = effect,
        Retry = effect == EffectCertainty.Unknown
            ? new RetryAdvice { Mode = RetryMode.Reconcile, ReconciliationOperation = "NodeService.GetOperation" }
            : new RetryAdvice { Mode = RetryMode.Never },
        Details = new ErrorDetails { State = new StateFailure { Reason = reason } },
    };
}
