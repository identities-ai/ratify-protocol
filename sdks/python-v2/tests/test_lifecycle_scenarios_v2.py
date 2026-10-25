"""lifecycle-scenarios.json: Part B scripts and the profile_scenarios
(single-device offline and dual-root), replayed against the in-memory
reference store (mirrors Go TestV2ConformanceLifecycleScenarios and
TestV2ConformanceProfileScenarios)."""
from __future__ import annotations

import copy
import copyreg
import pickle
import threading

import pytest

from corpus import b64, load
from v2_harness import BACKGROUND, Counts, FixedClock, build_verify_request, keys, populate_status_journal

from ratify_protocol_v2 import context_v2
from ratify_protocol_v2.challenge_claim_v2 import protocol_claim_id_v2
from ratify_protocol_v2.claim_store_v2 import claim_proof_bundle_v2
from ratify_protocol_v2.errors_v2 import V2ErrorClass, error_class_of
from ratify_protocol_v2.evaluation_progress_v2 import recover_interrupted_claim_v2
from ratify_protocol_v2.operation_context_v2 import session_context_v2_hash
from ratify_protocol_v2.protocol_v2 import decode_proof_bundle_v2
from ratify_protocol_v2.release_v2 import (
    CommittedV2Outcome,
    V2CheckpointAcknowledgement,
    V2ReceiptCheckpoint,
    V2ReleaseConfig,
    release_v2_decision,
)
from ratify_protocol_v2.signing_v2 import key_id_v2
from ratify_protocol_v2.types import HybridSignature
from ratify_protocol_v2.v2reference import approval_ledger as al
from ratify_protocol_v2.v2reference import offline_device as od
from ratify_protocol_v2.v2reference.device_state import DevicePrimaryTestOnly
from ratify_protocol_v2.v2reference.store import (
    HeadOfLineBlockedError,
    LogFrozenError,
    SignerUnavailableError,
    Store,
)
from ratify_protocol_v2.verification_receipt_v2 import (
    decode_verification_receipt_body_v2,
    decode_verification_receipt_v2,
    encode_verification_receipt_v2,
    verification_receipt_v2_digest,
)
from ratify_protocol_v2.verify_v2 import (
    V2_STAGE_COMMITTED,
    V2_STAGE_EVALUATING,
    V2_STAGE_PREFLIGHT,
    V2_STAGE_REPLAY,
    verify_proof_bundle_v2,
)

from ratify_protocol_v2 import _native  # noqa: E402

pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="the reference store signs receipts; signing needs ratify-protocol-native-v2")

FILE = load("lifecycle-scenarios.json")
SCENARIOS = FILE["scenarios"]
PROFILE_SCENARIOS = FILE["profile_scenarios"]


def test_lifecycle_corpus_shape():
    assert len(SCENARIOS) == 62
    assert sum(len(s["steps"]) for s in SCENARIOS) == 338
    assert len(PROFILE_SCENARIOS) == 29
    assert sum(len(s["steps"]) for s in PROFILE_SCENARIOS) == 283
    profiles = {}
    for s in PROFILE_SCENARIOS:
        profiles[s["profile"]] = profiles.get(s["profile"], 0) + 1
    assert set(profiles) == {"single_device_offline", "dual_root"}
    assert profiles["single_device_offline"] >= 16 and profiles["dual_root"] >= 13


class WrongEntryCheckpoint(V2ReceiptCheckpoint):
    """Reports acknowledgements for a different entry hash."""

    def __init__(self, inner):
        self.inner = inner

    def acknowledge_v2_receipt(self, ctx, log_id, sequence, previous, entry):
        return self.inner.acknowledge_v2_receipt(ctx, log_id, sequence, previous, entry)

    def get_v2_acknowledgement(self, ctx, log_id, sequence):
        ack = self.inner.get_v2_acknowledgement(ctx, log_id, sequence)
        entry = bytearray(ack.entry_hash)
        entry[0] ^= 1
        return V2CheckpointAcknowledgement(log_id=ack.log_id, sequence=ack.sequence, entry_hash=bytes(entry), timestamp=ack.timestamp)


class OwnerCapturingClaimStore:
    """Records the evaluator owner token a claim store returns to the
    creator, so a finalize step can call the store directly."""

    def __init__(self, inner):
        self.inner = inner
        self.owner = b""

    def claim_v2(self, ctx, claim):
        result = self.inner.claim_v2(ctx, claim)
        self.owner = bytes(result.owner_token or b"")
        return result

    def __getattr__(self, name):
        return getattr(self.inner, name)


def request_inputs(name: str) -> dict:
    return copy.deepcopy(FILE["requests"][name])


def check_committed(step: int, c: CommittedV2Outcome, want: dict) -> None:
    body = decode_verification_receipt_body_v2(c.receipt_body())
    assert (body.decision, body.decision_reason) == (want.get("decision", ""), want.get("decision_reason", "")), step
    for name in ("trust_assessment", "status_assessment", "context_assessment"):
        if want.get(name):
            assert getattr(body, name) == want[name], (step, name)
    horizon, _ = c.allow_horizon()
    assert horizon == want.get("allow_horizon", 0), step


def check_released_allowed(step: int, d) -> None:
    """Allowed compares the receiver's time only with the sealed exclusive
    deadlines, and changing returned copies never changes the decision."""

    def at(now):
        return d.allowed(BACKGROUND, FixedClock(now))

    horizon, is_allow = d.allow_horizon()
    assert is_allow == (d.decision() == "allow"), step
    if not is_allow:
        assert not at(d.release_time()), step
        return
    deadline = min(horizon, d.challenge_expires_at())
    assert at(d.release_time()) and at(deadline - 1) and not at(deadline) and not at(deadline + 1), step
    scope, wire = d.granted_scope(), d.receipt_wire()
    receipt = d.receipt()
    scope[:] = ["mutated"] * len(scope)
    wire = bytes(len(wire))
    receipt.decision, receipt.sequence = "deny", receipt.sequence + 1
    again = d.receipt()
    assert again.decision == "allow" and again.sequence == receipt.sequence - 1 and "mutated" not in d.granted_scope()
    assert at(d.release_time())
    with pytest.raises(AttributeError):
        d._decision = "allow"
    assert not at(-1) and not d.allowed(BACKGROUND, None)
    check_copies_not_actionable(step, d)


def check_copies_not_actionable(step: int, d) -> None:
    """Only the exact object release returned is actionable: copying,
    pickling, or re-creating a genuine released allow yields nothing that
    allowed() accepts (SPEC-v2 §1.3)."""
    now = FixedClock(d.release_time())
    assert copy.copy(d) is d and copy.deepcopy(d) is d, step
    with pytest.raises(TypeError):
        pickle.dumps(d)
    cls = type(d)
    for forged in (object.__new__(cls), cls.__new__(cls)):
        assert forged is not d and not forged.allowed(BACKGROUND, now) and forged.decision() == "", step
    # Reconstructing through copyreg's protocol 2 path also yields an
    # unregistered instance.
    rebuilt = copy._reconstruct(d, None, copyreg.__newobj__, (cls,), None)
    assert rebuilt is not d and not rebuilt.allowed(BACKGROUND, now), step


def check_release(step: int, result, want: dict) -> None:
    assert (result.status, result.reason) == (want.get("release_status", ""), want.get("release_reason", "")), step
    assert (result.decision is not None) == (result.status == "released"), step
    if result.decision is not None:
        d = result.decision
        receipt = d.receipt()
        assert d.decision() == want.get("decision", "") and d.release_time() == want.get("release_time", 0), step
        assert receipt.sequence == want.get("receipt_sequence", 0), step
        check_released_allowed(step, d)


@pytest.mark.parametrize("sc", SCENARIOS, ids=[s["name"] for s in SCENARIOS])
def test_lifecycle_scenario(sc):
    fx = keys()
    verifier_key = FILE["verifier_key"]
    store = Store(sc["start_time"], FILE["lease_seconds"], FILE["log_id"], fx.priv(verifier_key))
    committed: dict = {}
    receipts: dict = {}
    claim_ids: dict = {}
    request_of: dict = {}
    owners: dict = {}
    epoch_override = [0]
    config = V2ReleaseConfig(verifier_public_key=fx.pub[verifier_key], log_id=FILE["log_id"], claim_store=store, checkpoint=store)
    holder = {"store": store}

    def claim_store():
        if sc.get("rate_at_finalization"):
            return holder["store"].with_rate_at_finalization()
        return holder["store"]

    def recover_step(i, request, want):
        claim_id = claim_ids.get(request)
        if claim_id is None:
            # Never claimed: the request's own claim ID (claim_not_found).
            e = FILE["requests"][request]["expected_challenge"]
            claim_id = protocol_claim_id_v2(e["verifier_namespace"], e["replay_epoch"], b64(e["value_b64"]))
        try:
            outcome, err = recover_interrupted_claim_v2(BACKGROUND, holder["store"], claim_id), None
        except Exception as exc:  # noqa: BLE001
            outcome, err = None, exc
        if want.get("error_class"):
            assert error_class_of(err) == want["error_class"], (i, err)
            return
        assert err is None, (i, err)
        check_committed(i, outcome, want)
        committed[request] = outcome

    maps_lock = threading.Lock()

    def run_verify(i, name, mode, at, want):
        """One verify step; safe for concurrent use with mode "" (the maps it
        writes are guarded)."""
        request = request_inputs(name)
        request["now"] = holder["store"].now()
        if epoch_override[0] != 0:
            request["configured_replay_epoch"] = epoch_override[0]
        req, cb, _ = build_verify_request(request, b64(FILE["bundles_b64"][request["bundle"]]), Counts())
        cs = claim_store()
        cb.claim_store = cs
        if sc.get("rate_at_finalization"):
            cb.rate = cs
        claim_id = protocol_claim_id_v2(req.verifier_namespace, req.replay_epoch, req.expected.value)
        with maps_lock:
            claim_ids[name], request_of[claim_id] = claim_id, name
        vctx = context_v2.with_cancel(BACKGROUND)
        if mode == "cancel_before_claim":
            vctx.cancel()
        elif mode:
            provider = cb.status_evidence
            fired = [False]

            def scripted(c, r):
                if not fired[0]:
                    fired[0] = True
                    if mode == "cancel_during_status":
                        vctx.cancel()
                        raise c.err()
                    if mode == "recover_during_status":
                        holder["store"].set_time(at)
                        recover_step(i, name, want["recovered"])
                    elif mode in ("expire_lease_during_status", "regress_clock_during_status"):
                        holder["store"].set_time(at)
                    else:
                        raise AssertionError(f"unknown verify mode {mode}")
                return provider(c, r)

            cb.status_evidence = scripted
        try:
            return verify_proof_bundle_v2(vctx, req, cb)
        finally:
            vctx.cancel()

    for i, step in enumerate(sc["steps"]):
        want = step.get("expect", {})
        store = holder["store"]
        now = store.now()
        op = step["op"]
        if op == "set_time":
            store.set_time(step["time"])
        elif op == "set_ack_withheld":
            store.set_acknowledgement_withheld(step["withheld"])
        elif op == "verify":
            outcome = run_verify(i, step["request"], step.get("mode", ""), step.get("time", 0), want)
            assert outcome.stage == want.get("stage", ""), (i, outcome.error_class, outcome.error)
            assert outcome.error_class == want.get("error_class", ""), (i, outcome.error)
            if want.get("disposition"):
                assert outcome.disposition == want["disposition"], i
            if outcome.stage == V2_STAGE_COMMITTED:
                check_committed(i, outcome.committed, want)
                committed[step["request"]] = outcome.committed
        elif op == "verify_concurrent":
            names = step["requests"]
            results = [None] * len(names)
            barrier = threading.Barrier(len(names))

            def worker(k, name):
                barrier.wait()
                results[k] = run_verify(i, name, "", 0, want)

            threads = [threading.Thread(target=worker, args=(k, name)) for k, name in enumerate(names)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            got = []
            for k, outcome in enumerate(results):
                label = outcome.stage
                if outcome.stage in (V2_STAGE_PREFLIGHT, V2_STAGE_EVALUATING):
                    label += "/" + outcome.error_class
                got.append(label)
                if outcome.stage == V2_STAGE_COMMITTED:
                    committed[names[k]] = outcome.committed
            assert sorted(got) == want["outcomes"], (i, got)
        elif op == "claim_only":
            request = request_inputs(step["request"])
            bundle = decode_proof_bundle_v2(b64(FILE["bundles_b64"][request["bundle"]]))
            req, _, _ = build_verify_request(request, None, Counts())
            from ratify_protocol_v2.verify_v2_preflight import preflight_proof_bundle_v2

            pre = preflight_proof_bundle_v2(bundle, req.expected, req.context_policy, req.required_scope, req.verifier_namespace,
                                            req.replay_epoch, now, req.max_challenge_age_seconds, req.future_skew_seconds)
            capturing = OwnerCapturingClaimStore(claim_store())
            try:
                claim, disposition, _ = claim_proof_bundle_v2(BACKGROUND, capturing, bundle, pre, req.verifier_namespace,
                                                              req.replay_epoch, now)
                err = None
            except Exception as exc:  # noqa: BLE001
                claim, disposition, err = None, "", exc
            assert error_class_of(err) == want.get("error_class", "") and disposition == want.get("disposition", ""), (i, err)
            claim_ids[step["request"]] = claim.claim_id
            request_of[claim.claim_id] = step["request"]
            owners[step["request"]] = capturing.owner
        elif op == "acknowledge":
            receipt = decode_verification_receipt_v2(receipts[step["request"]])
            entry = bytearray(verification_receipt_v2_digest(receipt))
            if step["mode"] == "fork":
                entry[0] ^= 1
            elif step["mode"] != "exact":
                raise AssertionError(f"unknown acknowledge mode {step['mode']}")
            try:
                ack, err = store.acknowledge_v2_receipt(BACKGROUND, receipt.log_id, receipt.sequence,
                                                        receipt.previous_receipt_hash, bytes(entry)), None
            except Exception as exc:  # noqa: BLE001
                ack, err = None, exc
            if want.get("failed"):
                assert err is not None, (i, ack)
                continue
            assert err is None, (i, err)
            assert (ack.timestamp, ack.sequence, bytes(ack.entry_hash)) == (want.get("ack_timestamp", 0), receipt.sequence,
                                                                           bytes(entry)), (i, ack)
        elif op == "finalize":
            try:
                finalized, err = claim_store().finalize_v2_claim(
                    BACKGROUND, claim_ids[step["request"]], owners[step["request"]], b64(step.get("terminal_b64", "")),
                    b64(step.get("body_b64", "")), step.get("allow_valid_until", 0)), None
            except Exception as exc:  # noqa: BLE001
                finalized, err = False, exc
            if want.get("error_class"):
                assert not finalized and error_class_of(err) == want["error_class"], (i, err)
                continue
            assert err is None, (i, err)
            assert ("committed" if finalized else "identical") == want.get("finalize_result", ""), i
        elif op == "recover_direct":
            try:
                recovered, err = claim_store().recover_interrupted_v2_claim(
                    BACKGROUND, claim_ids[step["request"]], b64(step.get("terminal_b64", "")),
                    b64(step.get("body_b64", ""))), None
            except Exception as exc:  # noqa: BLE001
                recovered, err = False, exc
            if want.get("error_class"):
                assert not recovered and error_class_of(err) == want["error_class"], (i, err)
                continue
            assert err is None, (i, err)
            assert ("committed" if recovered else "identical") == want.get("finalize_result", ""), i
        elif op == "recover":
            recover_step(i, step["request"], want)
        elif op == "publish":
            c = committed[step["request"]]
            if step.get("mode") == "signer_failure":
                store.set_signer_failure(True)
            try:
                wire, err = store.publish_v2_receipt(BACKGROUND, c.claim_id(), c.receipt_body()), None
            except Exception as exc:  # noqa: BLE001
                wire, err = None, exc
            store.set_signer_failure(False)
            if want.get("failed"):
                reasons = {"head_of_line_blocked": HeadOfLineBlockedError, "signer_unavailable": SignerUnavailableError,
                           "log_frozen": LogFrozenError}
                assert wire is None and isinstance(err, reasons[want["publish_error"]]), (i, err)
                continue
            assert err is None, (i, err)
            receipt = decode_verification_receipt_v2(wire)
            assert receipt.sequence == want.get("receipt_sequence", 0), i
            if step.get("mode") == "corrupt_signature":
                ed = bytearray(receipt.signature.ed25519)
                ed[0] ^= 1
                receipt.signature = HybridSignature(ed25519=bytes(ed), ml_dsa_65=receipt.signature.ml_dsa_65)
                wire = encode_verification_receipt_v2(receipt)
            receipts[step["request"]] = wire
        elif op == "abandon":
            got = [request_of[cid] for cid in store.abandon_pending_receipts()]
            assert got == list(want.get("abandoned") or []), i
        elif op == "restore":
            if step["mode"] == "exact":
                store = store.clone()
            elif step["mode"] == "lost_state_epoch_bump":
                store = Store(now, FILE["lease_seconds"], step["log_id"], fx.priv(verifier_key))
                epoch_override[0] = step["replay_epoch"]
                config.log_id = step["log_id"]
            else:
                raise AssertionError(f"unknown restore mode {step['mode']}")
            holder["store"] = store
            config.claim_store, config.checkpoint = store, store
        elif op == "plant_release":
            store.plant_release_test_only(committed[step["request"]].claim_id(), step["time"])
        elif op in ("release", "release_forged"):
            c = committed.get(step.get("request", ""))
            receipt = receipts.get(step.get("receipt_of") or step.get("request", ""))
            cfg = copy.copy(config)
            if step.get("checkpoint") == "wrong_entry":
                cfg.checkpoint = WrongEntryCheckpoint(store)
            if step.get("mode") == "no_receipt":
                receipt = None
            if op == "release_forged":
                c, receipt = object.__new__(CommittedV2Outcome), None
            check_release(i, release_v2_decision(BACKGROUND, c, receipt, cfg), want)
        else:
            raise AssertionError(f"unknown op {op}")


# ---------------------------------------------------------------------------
# Profile scenarios


class DeviceClock:
    """The device's one security clock: whichever primary store is current."""

    def __init__(self, holder):
        self.holder = holder

    def authoritative_time_v2(self, ctx):
        return self.holder["store"].authoritative_time_v2(ctx)


def device_error_class(err) -> str:
    if err is None:
        return ""
    for name, cls in (("power_loss", od.DevicePowerLossError), ("storage_full", od.DeviceStorageFullError),
                      ("state_mismatch", od.DeviceStateMismatchError), ("frozen", od.DeviceFrozenError)):
        if isinstance(err, cls):
            return name
    if error_class_of(err) == V2ErrorClass.CLOCK_REGRESSED:
        return "clock_regressed"
    return f"unexpected: {err!r}"


LEDGER_ERRORS = {
    "approval_set_invalid": al.ApprovalSetInvalidError, "not_released": al.ApprovalNotReleasedError,
    "action_mismatch": al.ApprovalActionMismatchError, "root_mismatch": al.ApprovalRootMismatchError,
    "slot_filled": al.ApprovalSlotFilledError, "approval_reused": al.ApprovalReusedError,
    "incomplete": al.ApprovalIncompleteError, "expired": al.ApprovalExpiredError,
    "already_executed": al.ApprovalAlreadyExecutedError,
}


def ledger_error_class(err) -> str:
    if err is None:
        return ""
    for name, cls in LEDGER_ERRORS.items():
        if type(err) is cls:
            return name
    return f"unexpected: {err!r}"


def _call(fn, *args):
    try:
        return fn(*args), None
    except Exception as exc:  # noqa: BLE001
        return None, exc


@pytest.mark.parametrize("sc", PROFILE_SCENARIOS, ids=[s["name"] for s in PROFILE_SCENARIOS])
def test_profile_scenario(sc):
    fx = keys()
    verifier_key = FILE["verifier_key"]
    holder = {"store": Store(sc["start_time"], FILE["lease_seconds"], FILE["log_id"], fx.priv(verifier_key))}
    primary = device = component = uplink = None
    if sc["profile"] == "single_device_offline":
        holder["store"].set_acknowledgement_withheld(True)
        dev = sc["device"]
        component = od.DeviceComponentTestOnly(b64(dev["component_seed_b64"]), dev["capacity"], DeviceClock(holder))
        primary = DevicePrimaryTestOnly(holder["store"], dev["replay_epoch"])
        device = od.DeviceCheckpointTestOnly(primary, component, component.public_key())
        device.provision()
        uplink = od.DeviceUplinkTestOnly(device)
    ledger = al.ApprovalLedgerTestOnly()
    set_id = [""]
    committed: dict = {}
    receipts: dict = {}
    decisions: dict = {}
    snapshots: dict = {}
    for i, step in enumerate(sc["steps"]):
        want = step.get("expect", {})
        store = holder["store"]
        op = step["op"]
        if op == "set_time":
            store.set_time(step["time"])
        elif op == "set_ack_withheld":
            store.set_acknowledgement_withheld(step["withheld"])
        elif op == "verify":
            request = request_inputs(step["request"])
            request["now"] = store.now()
            req, cb, _ = build_verify_request(request, b64(FILE["bundles_b64"][request["bundle"]]), Counts())
            cb.claim_store = store
            if sc.get("rate_at_finalization"):
                rate_store = store.with_rate_at_finalization()
                cb.claim_store, cb.rate = rate_store, rate_store
            outcome = verify_proof_bundle_v2(BACKGROUND, req, cb)
            assert (outcome.stage, outcome.error_class) == (want.get("stage", ""), want.get("error_class", "")), (i, outcome.error)
            if outcome.stage == V2_STAGE_COMMITTED:
                check_committed(i, outcome.committed, want)
                committed[step["request"]] = outcome.committed
        elif op == "publish":
            c = committed[step["request"]]
            wire = store.publish_v2_receipt(BACKGROUND, c.claim_id(), c.receipt_body())
            assert decode_verification_receipt_v2(wire).sequence == want.get("receipt_sequence", 0), i
            receipts[step["request"]] = wire
        elif op == "release":
            cfg = V2ReleaseConfig(verifier_public_key=fx.pub[verifier_key], log_id=FILE["log_id"], claim_store=store, checkpoint=store)
            if step.get("checkpoint") == "device":
                cfg.checkpoint = device
            result = release_v2_decision(BACKGROUND, committed.get(step["request"]), receipts.get(step["request"]), cfg)
            check_release(i, result, want)
            decisions[step["request"]] = result.decision
        elif op == "device_power_loss":
            component.set_power_loss({"before_commit": od.DEVICE_POWER_LOSS_BEFORE_COMMIT,
                                      "after_commit": od.DEVICE_POWER_LOSS_AFTER_COMMIT}[step["mode"]])
        elif op == "device_submit":
            acknowledged, err = device.submit_pending(BACKGROUND)
            assert device_error_class(err) == want.get("device_error", "") and acknowledged == list(want.get("acknowledged") or []), (i, err, acknowledged)
        elif op == "device_resubmit":
            ack, err = _call(device.resubmit, BACKGROUND, step["sequence"])
            assert device_error_class(err) == want.get("device_error", ""), (i, err)
            if err is None:
                assert ack.timestamp == want.get("ack_time", 0), i
        elif op == "device_startup":
            assert device.startup() == want.get("device_status", ""), i
        elif op == "snapshot":
            snapshots[step["snapshot"]] = primary.clone()
        elif op == "restore":
            now = store.now()
            primary = snapshots[step["snapshot"]].clone()
            holder["store"] = primary.store
            holder["store"].set_time(now)
            device = od.DeviceCheckpointTestOnly(primary, component, component.public_key())
            uplink = od.DeviceUplinkTestOnly(device)
        elif op == "stage_status":
            populate_status_journal(primary.journal, request_inputs(step["request"]))
        elif op == "plant_release":
            store.plant_release_test_only(committed[step["request"]].claim_id(), step["time"])
        elif op == "corrupt_state":
            od.corrupt_sealed_state_test_only(store, committed[step["request"]].claim_id())
        elif op == "upload":
            assert uplink.upload(BACKGROUND) == list(want.get("uploaded") or []), i
        elif op == "ledger_open":
            s = step["approval_set"]
            derived = session_context_v2_hash(s["verifier_id"], s["workspace_id"], fx.id[s["agent_key"]], s["session_id"],
                                              s["id"], b64(s["request_hash_b64"]))
            assert derived == b64(s["session_context_b64"]), i
            _, err = _call(ledger.open, al.ApprovalSetTestOnly(
                approval_set_id=s["id"], verifier_id=s["verifier_id"], workspace_id=s["workspace_id"], session_id=s["session_id"],
                agent_public_key=fx.pub[s["agent_key"]], required_scope=s["required_scope"], request_hash=b64(s["request_hash_b64"]),
                roots=(fx.pub[s["root_keys"][0]], fx.pub[s["root_keys"][1]])))
            assert ledger_error_class(err) == want.get("ledger_error", ""), (i, err)
            if err is None:
                set_id[0] = s["id"]
        elif op == "ledger_record":
            target = step.get("set") or set_id[0]
            request = FILE["requests"][step["request"]]
            complete, err = _call(ledger.record_approval, target, step["slot"], decisions.get(step["request"]),
                                  b64(FILE["bundles_b64"][request["bundle"]]))
            assert ledger_error_class(err) == want.get("ledger_error", ""), (i, err)
            assert bool(complete) == bool(want.get("ledger_complete", False)), i
        elif op == "ledger_record_concurrent":
            errs = [None] * len(step["requests"])

            def record(slot, name):
                _, errs[slot] = _call(ledger.record_approval, set_id[0], slot, decisions[name],
                                      b64(FILE["bundles_b64"][FILE["requests"][name]["bundle"]]))

            threads = [threading.Thread(target=record, args=(slot, name)) for slot, name in enumerate(step["requests"])]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert errs == [None] * len(errs), (i, errs)
            first = step["requests"][0]
            complete = ledger.record_approval(set_id[0], 0, decisions[first], b64(FILE["bundles_b64"][FILE["requests"][first]["bundle"]]))
            assert complete == bool(want.get("ledger_complete", False)), i
        elif op == "ledger_execute":
            target = step.get("set") or set_id[0]
            _, err = _call(ledger.execute, BACKGROUND, target, store)
            assert ledger_error_class(err) == want.get("ledger_error", ""), (i, err)
        elif op == "ledger_execute_concurrent":
            results = []
            lock = threading.Lock()

            def execute():
                _, err = _call(ledger.execute, BACKGROUND, set_id[0], store)
                with lock:
                    results.append(err)

            threads = [threading.Thread(target=execute) for _ in range(step["count"])]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert all(e is None or isinstance(e, al.ApprovalAlreadyExecutedError) for e in results), results
            assert sum(1 for e in results if e is None) == want.get("executed", 0), i
        else:
            raise AssertionError(f"unknown profile op {op}")


def test_cancellation_after_claim_leaves_claim_recoverable():
    """Cancelling after the claim commits nothing: evaluating/
    evaluation_cancelled, an exact retry sees the claim in progress, and
    lease-expiry recovery terminalizes it (SPEC-v2 §6.11)."""
    fx = keys()
    start = 1800000000
    store = Store(start, FILE["lease_seconds"], FILE["log_id"], fx.priv("verifier"))
    request = request_inputs("A")
    request["now"] = start
    bundle = b64(FILE["bundles_b64"][request["bundle"]])
    ctx = context_v2.with_cancel(BACKGROUND)
    req, cb, _ = build_verify_request(request, bundle, Counts())
    cb.claim_store = store
    provider = cb.status_evidence

    def cancelling(c, r):
        ctx.cancel()
        provider(c, r)
        err = c.err()
        if err is not None:
            raise err
        return provider(c, r)

    cb.status_evidence = cancelling
    outcome = verify_proof_bundle_v2(ctx, req, cb)
    assert outcome.stage == V2_STAGE_EVALUATING and outcome.error_class == V2ErrorClass.EVALUATION_CANCELLED
    assert outcome.committed is None and outcome.error is not None
    retry_req, retry_cb, _ = build_verify_request(request, bundle, Counts())
    retry_cb.claim_store = store
    retry = verify_proof_bundle_v2(BACKGROUND, retry_req, retry_cb)
    assert retry.stage == V2_STAGE_REPLAY and retry.disposition == "in_progress"
    with pytest.raises(Exception) as live:
        recover_interrupted_claim_v2(BACKGROUND, store, outcome.claim.claim_id)
    assert error_class_of(live.value) == V2ErrorClass.CLAIM_LEASE_LIVE
    store.set_time(start + FILE["lease_seconds"])
    recovered = recover_interrupted_claim_v2(BACKGROUND, store, outcome.claim.claim_id)
    assert decode_verification_receipt_body_v2(recovered.receipt_body()).decision_reason == "evaluation_interrupted"
