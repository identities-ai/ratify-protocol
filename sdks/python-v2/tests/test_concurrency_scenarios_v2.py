"""concurrency-scenarios.json: shared concurrent workloads against the
in-memory reference store, with outcome invariants (mirrors Go
TestV2ConformanceConcurrencyScenarios).

Every participant is a threading.Thread; all of them wait on one
threading.Barrier and start together. The verify API is synchronous, so no
asyncio is involved. Under the GIL, threads interleave at bytecode
boundaries and at blocking calls (the store's RLock, time.sleep), and the
native extension releases the GIL while it verifies a hybrid signature, so
one participant's store operations run between another's preflight, claim,
evaluation and finalization: the store's lock really is contended and the
interleavings vary between iterations (the outcomes printed per scenario
show which ones occurred; for example verifications regularly see another
verification's claim still in progress, and the owner, the clock and the
recoverers each win the lease race in some iterations). Python code itself
never runs in parallel, so the contention is coarser than in Go.

Set RATIFY_RACE_ITERATIONS to change the per-scenario iteration count; the
default is the file's default_iterations. Run with -s to see the distinct
outcomes per group across iterations.
"""
from __future__ import annotations

import copy
import os
import threading
import time
from collections import Counter

import pytest

from corpus import b64, load
from test_lifecycle_scenarios_v2 import OwnerCapturingClaimStore, check_committed
from v2_harness import BACKGROUND, Counts, build_verify_request, keys

from ratify_protocol_v2 import context_v2
from ratify_protocol_v2.challenge_claim_v2 import protocol_claim_id_v2
from ratify_protocol_v2.claim_store_v2 import claim_proof_bundle_v2
from ratify_protocol_v2.errors_v2 import error_class_of
from ratify_protocol_v2.evaluation_progress_v2 import recover_interrupted_claim_v2, resume_committed_claim_v2
from ratify_protocol_v2.protocol_v2 import decode_proof_bundle_v2
from ratify_protocol_v2.release_v2 import V2ReleaseConfig, release_v2_decision
from ratify_protocol_v2.v2reference.store import HeadOfLineBlockedError, Store
from ratify_protocol_v2.verification_receipt_v2 import (
    decode_verification_receipt_body_v2,
    decode_verification_receipt_v2,
    verification_receipt_v2_digest,
)
from ratify_protocol_v2.verify_v2 import V2_STAGE_COMMITTED, V2_STAGE_REPLAY, verify_proof_bundle_v2
from ratify_protocol_v2.verify_v2_preflight import preflight_proof_bundle_v2

from ratify_protocol_v2 import _native  # noqa: E402

pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="the reference store signs receipts; signing needs ratify-protocol-native-v2")

FILE = load("concurrency-scenarios.json")
SCENARIOS = FILE["scenarios"]
INPUTS = load(FILE["inputs"])


def race_iterations() -> int:
    s = os.environ.get("RATIFY_RACE_ITERATIONS", "")
    if s:
        if not s.isdigit() or int(s) < 1:
            raise AssertionError(f"RATIFY_RACE_ITERATIONS={s!r} is not a positive integer")
        return int(s)
    return FILE["default_iterations"]


def test_concurrency_corpus_shape():
    assert FILE["version"] == 1 and SCENARIOS
    assert FILE["inputs"] == "lifecycle-scenarios.json"


def _call(fn, *args):
    try:
        return fn(*args), None
    except Exception as exc:  # noqa: BLE001
        return None, exc


def error_label(err) -> str:
    return "error/" + error_class_of(err)


class RaceIteration:
    """The state of one iteration of one scenario."""

    def __init__(self, sc: dict, fx, store: Store):
        self.fx = fx
        self.store = store
        self.rate_store = bool(sc.get("rate_at_finalization"))
        self.lock = threading.Lock()
        self.committed: dict = {}
        self.receipts: dict = {}
        self.owners: dict = {}
        self.recorded: dict = {}  # claim ID -> committed receipt body
        self.recorded_at: list = []  # claim IDs in first-recorded order

    def claim_store(self):
        if self.rate_store:
            return self.store.with_rate_at_finalization()
        return self.store

    @staticmethod
    def claim_id(request: str) -> str:
        """The protocol claim ID of request: its verifier namespace, replay
        epoch and challenge, claimed or not, whichever step claimed it."""
        e = INPUTS["requests"][request]["expected_challenge"]
        return protocol_claim_id_v2(e["verifier_namespace"], e["replay_epoch"], b64(e["value_b64"]))

    def record(self, claim_id: str, body: bytes) -> None:
        with self.lock:
            if claim_id not in self.recorded:
                self.recorded[claim_id] = bytes(body)
                self.recorded_at.append(claim_id)

    def record_resumed(self, c) -> bool:
        """Record a resumed handoff as a committed result of its claim;
        False when its body differs from the one recorded."""
        with self.lock:
            prior = self.recorded.get(c.claim_id())
            if prior is not None:
                return prior == bytes(c.receipt_body())
            self.recorded[c.claim_id()] = bytes(c.receipt_body())
            self.recorded_at.append(c.claim_id())
            return True

    def record_outcome(self, request: str, c) -> None:
        with self.lock:
            self.committed[request] = c
        self.record(c.claim_id(), c.receipt_body())

    def prepare_verify(self, name: str):
        """One verification of request name at the current store clock,
        built on the test thread before any participant starts."""
        request = copy.deepcopy(INPUTS["requests"][name])
        request["now"] = self.store.now()
        req, cb, _ = build_verify_request(request, b64(INPUTS["bundles_b64"][request["bundle"]]), Counts())
        cs = self.claim_store()
        cb.claim_store = cs
        if self.rate_store:
            cb.rate = cs
        return req, cb

    def verify_label(self, ctx, name: str, req, cb):
        outcome = verify_proof_bundle_v2(ctx, req, cb)
        if outcome.stage == V2_STAGE_COMMITTED:
            self.record_outcome(name, outcome.committed)
            body, err = _call(decode_verification_receipt_body_v2, outcome.committed.receipt_body())
            if err is not None:
                return "undecodable committed body", outcome
            return f"committed/{body.decision}/{body.decision_reason}", outcome
        if outcome.stage == V2_STAGE_REPLAY:
            return f"replay/{outcome.disposition}", outcome
        return f"{outcome.stage}/{outcome.error_class}", outcome

    def release_label(self, ctx, request: str, handoff=None) -> str:
        with self.lock:
            c, receipt = self.committed.get(request), self.receipts.get(request)
        if handoff is not None:
            c = handoff
        verifier_key = INPUTS["verifier_key"]
        config = V2ReleaseConfig(verifier_public_key=self.fx.pub[verifier_key], log_id=INPUTS["log_id"], claim_store=self.store,
                                 checkpoint=self.store)
        result = release_v2_decision(ctx, c, receipt, config)
        if result.status != "released":
            return f"{result.status}/{result.reason}"
        d = result.decision
        r, err = _call(d.receipt)
        if err is not None:
            return "released with an undecodable receipt"
        return f"released/{d.decision()}/{d.release_time()}/{r.sequence}"

    def preflight_and_claim(self, ctx, name: str, store):
        """Preflight and claim request name at the store clock, as the
        lifecycle claim_only step."""
        request = copy.deepcopy(INPUTS["requests"][name])
        bundle = decode_proof_bundle_v2(b64(INPUTS["bundles_b64"][request["bundle"]]))
        now = self.store.now()
        req, _, _ = build_verify_request(request, None, Counts())
        pre, err = _call(preflight_proof_bundle_v2, bundle, req.expected, req.context_policy, req.required_scope,
                         req.verifier_namespace, req.replay_epoch, req.verifier_id, now, req.max_challenge_age_seconds,
                         req.future_skew_seconds)
        if err is not None:
            return None, None, ("preflight", err)
        result, err = _call(claim_proof_bundle_v2, ctx, store, bundle, pre, req.verifier_namespace, req.replay_epoch, now)
        if err is not None:
            return None, None, ("claim", err)
        claim, disposition, _ = result
        return claim, disposition, None

    def step(self, i: int, s: dict, want: dict) -> None:
        """One setup or after step; want overrides s["expect"]."""
        op = s["op"]
        if op == "set_time":
            self.store.set_time(s["time"])
        elif op == "set_ack_withheld":
            self.store.set_acknowledgement_withheld(s["withheld"])
        elif op == "verify":
            req, cb = self.prepare_verify(s["request"])
            _, outcome = self.verify_label(BACKGROUND, s["request"], req, cb)
            assert outcome.stage == want.get("stage", "") and outcome.error_class == want.get("error_class", ""), \
                (i, s["request"], outcome.stage, outcome.error_class, outcome.disposition, outcome.error, want)
            if want.get("disposition"):
                assert outcome.disposition == want["disposition"], (i, outcome.disposition, want)
            if outcome.stage == V2_STAGE_COMMITTED:
                check_committed(i, outcome.committed, want)
        elif op == "claim_only":
            capturing = OwnerCapturingClaimStore(self.claim_store())
            claim, disposition, failed = self.preflight_and_claim(BACKGROUND, s["request"], capturing)
            assert failed is None or failed[0] == "claim", (i, failed)
            err = failed[1] if failed else None
            assert error_class_of(err) == want.get("error_class", "") and (disposition or "") == want.get("disposition", ""), \
                (i, disposition, err, want)
            assert claim.claim_id == self.claim_id(s["request"]), (i, "claim ID is not the request's protocol claim ID")
            self.owners[s["request"]] = capturing.owner
        elif op == "recover":
            outcome, err = _call(recover_interrupted_claim_v2, BACKGROUND, self.store, self.claim_id(s["request"]))
            if want.get("error_class"):
                assert error_class_of(err) == want["error_class"], (i, err, want)
                return
            assert err is None, (i, err)
            check_committed(i, outcome, want)
            self.record_outcome(s["request"], outcome)
        elif op == "resume":
            outcome, err = _call(resume_committed_claim_v2, BACKGROUND, self.store, self.claim_id(s["request"]))
            if want.get("error_class"):
                assert error_class_of(err) == want["error_class"], (i, err, want)
                return
            assert err is None, (i, err)
            check_committed(i, outcome, want)
            assert self.record_resumed(outcome), (i, "the resumed body differs from the committed one")
            self.committed[s["request"]] = outcome
        elif op == "publish":
            c = self.committed[s["request"]]
            wire = self.store.publish_v2_receipt(BACKGROUND, c.claim_id(), c.receipt_body())
            receipt = decode_verification_receipt_v2(wire)
            assert receipt.sequence == want.get("receipt_sequence", 0), (i, receipt.sequence, want)
            self.receipts[s["request"]] = wire
        elif op == "release":
            got = self.release_label(BACKGROUND, s["request"])
            want_label = f"{want.get('release_status', '')}/{want.get('release_reason', '')}"
            if want.get("release_status") == "released":
                want_label = f"released/{want.get('decision', '')}/{want.get('release_time', 0)}/{want.get('receipt_sequence', 0)}"
            assert got == want_label, (i, got, want_label)
        else:
            raise AssertionError(f"step {i}: op {op} is not a concurrency setup or after step")

    def participant(self, p: dict, prepared) -> str:
        """One participant's operation; returns its label. prepared runs a
        verify participant built before the start barrier."""
        ctx = BACKGROUND
        op = p["op"]
        if op == "verify":
            return prepared()
        if op == "claim_only":
            _, disposition, failed = self.preflight_and_claim(ctx, p["request"], self.claim_store())
            if failed is not None:
                stage, err = failed
                return f"preflight/{error_class_of(err)}" if stage == "preflight" else error_label(err)
            return disposition
        if op in ("finalize", "recover_direct"):
            claim_id = self.claim_id(p["request"])
            with self.lock:
                owner = self.owners.get(p["request"], b"")
            body, terminal = b64(p["body_b64"]), b64(p["terminal_b64"])
            if op == "finalize":
                ok, err = _call(self.claim_store().finalize_v2_claim, ctx, claim_id, owner, terminal, body,
                                p.get("allow_valid_until", 0))
            else:
                ok, err = _call(self.claim_store().recover_interrupted_v2_claim, ctx, claim_id, terminal, body)
            if err is not None:
                return error_label(err)
            if ok:
                self.record(claim_id, body)
                return "committed"
            return "identical"
        if op == "recover":
            outcome, err = _call(recover_interrupted_claim_v2, ctx, self.store, self.claim_id(p["request"]))
            if err is not None:
                return error_label(err)
            self.record_outcome(p["request"], outcome)
            body, err = _call(decode_verification_receipt_body_v2, outcome.receipt_body())
            if err is not None:
                return "undecodable recovered body"
            return f"committed/{body.decision}/{body.decision_reason}"
        if op == "resume":
            outcome, err = _call(resume_committed_claim_v2, ctx, self.store, self.claim_id(p["request"]))
            if err is not None:
                return error_label(err)
            if not self.record_resumed(outcome):
                return "resumed a body other than the committed one"
            if p.get("mode") == "release":
                return self.release_label(ctx, p["request"], outcome)
            body, err = _call(decode_verification_receipt_body_v2, outcome.receipt_body())
            if err is not None:
                return "undecodable resumed body"
            return f"committed/{body.decision}/{body.decision_reason}"
        if op == "release":
            return self.release_label(ctx, p["request"])
        if op == "acknowledge":
            with self.lock:
                wire = self.receipts[p["request"]]
            receipt, err = _call(decode_verification_receipt_v2, wire)
            if err is not None:
                return "undecodable receipt"
            entry, err = _call(verification_receipt_v2_digest, receipt)
            if err is not None:
                return "undigestable receipt"
            ack, err = _call(self.store.acknowledge_v2_receipt, ctx, receipt.log_id, receipt.sequence,
                             receipt.previous_receipt_hash, entry)
            if err is not None:
                return "refused"
            return f"acknowledged/{ack.timestamp}"
        if op == "set_time":
            self.store.set_time(p["time"])
            return "done"
        return f"unknown op {op}"

    def receipt_log_contiguous(self) -> None:
        """Publish every recorded result, retrying entries blocked behind an
        earlier one, and require sequences 1..k."""
        published: dict = {}
        progress = True
        while progress:
            progress = False
            for claim_id in self.recorded_at:
                if claim_id in published:
                    continue
                try:
                    wire = self.store.publish_v2_receipt(BACKGROUND, claim_id, self.recorded[claim_id])
                except HeadOfLineBlockedError:
                    continue
                published[claim_id], progress = wire, True
        sequences = []
        for claim_id in self.recorded_at:
            wire = published.get(claim_id)
            assert wire is not None, f"claim {claim_id} never published (head of line blocked)"
            receipt = decode_verification_receipt_v2(wire)
            again = self.store.publish_v2_receipt(BACKGROUND, claim_id, self.recorded[claim_id])
            assert again == wire, f"claim {claim_id} republished differently"
            sequences.append(receipt.sequence)
        sequences.sort()
        assert sequences == list(range(1, len(sequences) + 1)), f"receipt sequences {sequences}, want 1..{len(sequences)}"


def check_invariant(inv: dict, labels: dict, everything: list) -> None:
    def of(groups):
        if not groups:
            return everything
        return [label for g in groups for label in labels.get(g, [])]

    kind = inv["kind"]
    if kind == "allowed":
        for label in of(inv.get("groups")):
            assert label in inv["outcomes"], f"outcome {label!r} of {inv.get('groups')} is not one of {inv['outcomes']}"
    elif kind == "count":
        n = sum(1 for label in of(inv.get("groups")) if label in inv["outcomes"])
        if "equals" in inv:
            assert n == inv["equals"], f"{n} outcomes of {inv.get('groups')} are in {inv['outcomes']}, want exactly {inv['equals']}"
        if "at_most" in inv:
            assert n <= inv["at_most"], f"{n} outcomes of {inv.get('groups')} are in {inv['outcomes']}, want at most {inv['at_most']}"
    elif kind == "all_equal":
        got = of(inv.get("groups"))
        assert all(label == got[0] for label in got), f"outcomes of {inv.get('groups')} differ: {got}"
    elif kind == "one_winner":
        winners = [g for g in inv["by_group"] if any(label in inv["winning"] for label in labels.get(g, []))]
        assert len(winners) <= 1, f"winning groups {winners}, want at most one"
        for g, rule in inv["by_group"].items():
            allowed = rule["if_winner"] if g in winners else rule["if_loser"]
            for label in labels.get(g, []):
                assert label in allowed, f"group {g} (winners {winners}) has outcome {label!r}, not one of {allowed}"
    else:
        raise AssertionError(f"unknown invariant kind {kind}")


def measure_verification(sc: dict, fx, target: str) -> float:
    """Seconds of one uncancelled verification of the request that group
    target verifies, on a scratch store."""
    for p in sc["participants"]:
        if p["group"] != target or p["op"] != "verify":
            continue
        store = Store(sc["start_time"], INPUTS["lease_seconds"], INPUTS["log_id"], fx.priv(INPUTS["verifier_key"]))
        it = RaceIteration(sc, fx, store)
        req, cb = it.prepare_verify(p["request"])
        began = time.perf_counter()
        it.verify_label(BACKGROUND, p["request"], req, cb)
        return time.perf_counter() - began
    raise AssertionError(f"cancel target {target} has no verify participant")


@pytest.mark.parametrize("sc", SCENARIOS, ids=[s["name"] for s in SCENARIOS])
def test_concurrency_scenario(sc):
    fx = keys()
    iterations = race_iterations()
    # seen counts each distinct outcome per group across iterations, printed
    # so a run with -s (or a failure report) shows which interleavings
    # occurred.
    seen: Counter = Counter()
    # span is one uncancelled verification of a cancel target, measured once.
    span = 0.0
    try:
        for iteration in range(iterations):
            store = Store(sc["start_time"], INPUTS["lease_seconds"], INPUTS["log_id"], fx.priv(INPUTS["verifier_key"]))
            it = RaceIteration(sc, fx, store)
            for i, s in enumerate(sc.get("setup") or []):
                it.step(i, s, s.get("expect", {}))
            # Prepare every participant on the test thread, then release
            # them together.
            slots = []
            cancels: dict = {}
            for p in sc["participants"]:
                for _ in range(p.get("count", 1)):
                    prepared = None
                    if p["op"] == "verify":
                        req, cb = it.prepare_verify(p["request"])
                        vctx = context_v2.with_cancel(BACKGROUND)
                        cancels.setdefault(p["group"], []).append(vctx)

                        def prepared(vctx=vctx, name=p["request"], req=req, cb=cb):
                            return it.verify_label(vctx, name, req, cb)[0]

                    def run(p=p, prepared=prepared):
                        return it.participant(p, prepared)

                    if p["op"] == "cancel":
                        # Spread the signal over the target's verification
                        # across iterations: 0 to 1.2 times its duration.
                        if span == 0.0:
                            span = measure_verification(sc, fx, p["target"])
                        delay = span * (iteration % 13) / 10

                        def run(target=p["target"], delay=delay):
                            time.sleep(delay)
                            for c in cancels.get(target, []):
                                c.cancel()
                            return "done"

                    slots.append((p["group"], run))
            results = [None] * len(slots)
            failures = []
            barrier = threading.Barrier(len(slots))

            def worker(k, run):
                barrier.wait()
                try:
                    results[k] = run()
                except BaseException as exc:  # noqa: BLE001
                    failures.append(exc)

            threads = [threading.Thread(target=worker, args=(k, run)) for k, (_, run) in enumerate(slots)]
            # The thread that reaches the barrier last keeps the GIL and runs
            # first, so a fixed start order would let one participant (the
            # clock, say) always go first. Rotating the start order per
            # iteration varies which participant that is.
            shift = iteration % len(threads)
            for t in threads[shift:] + threads[:shift]:
                t.start()
            for t in threads:
                t.join()
            for group in cancels.values():
                for c in group:
                    c.cancel()
            if failures:
                raise failures[0]
            labels: dict = {}
            everything = []
            for k, (group, _) in enumerate(slots):
                labels.setdefault(group, []).append(results[k])
                everything.append(results[k])
                seen[f"{group}:{results[k]}"] += 1
            for inv in sc["invariants"]:
                try:
                    if inv["kind"] == "receipt_log_contiguous":
                        it.receipt_log_contiguous()
                    else:
                        check_invariant(inv, labels, everything)
                except AssertionError as exc:
                    raise AssertionError(f"iteration {iteration}: invariant {inv['kind']}: {exc} (outcomes {labels})") from exc
            for i, s in enumerate(sc.get("after") or []):
                want = s.get("expect", {})
                by = s.get("expect_by_outcome")
                if by is not None:
                    got = labels.get(by["group"], [])
                    assert len(got) == 1, f"iteration {iteration}: expect_by_outcome group {by['group']} has {len(got)} participants"
                    assert got[0] in by["cases"], f"iteration {iteration}: after step {i}: no case for outcome {got[0]}"
                    want = by["cases"][got[0]]
                it.step(i, s, want)
    finally:
        print(f"\n{sc['name']}: {iterations} iterations, outcomes {dict(sorted(seen.items()))}")
