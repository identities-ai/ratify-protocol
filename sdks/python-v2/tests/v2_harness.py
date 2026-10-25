"""Shared scripted dependencies for the verifier-ordering, lifecycle,
profile, issuance, and transaction-verification runners. Mirrors the Go
conformance harness (v2_conformance_ordering_test.go)."""
from __future__ import annotations

from dataclasses import dataclass, fields
from functools import lru_cache
from typing import Optional

from corpus import b64, load, pubkey

from ratify_protocol_v2 import context_v2
from ratify_protocol_v2.claim_store_v2 import (
    V2_CLAIM_CREATED,
    V2_CLAIM_IN_PROGRESS,
    V2_CLAIM_TERMINAL_REPLAY,
    ClaimProofConflictError,
    ClaimStoreV2,
    V2ClaimResult,
    V2RateReservationStore,
)
from ratify_protocol_v2.errors_v2 import V2Error, V2ErrorClass
from ratify_protocol_v2.v2reference.trust_registry import TrustRegistry
from ratify_protocol_v2.verify_v2 import V2TrustResolution, V2VerifyCallbacks, V2VerifyRequest
from ratify_protocol_v2.verify_v2_preflight import ExpectedChallengeV2

BACKGROUND = context_v2.background()

COUNT_NAMES = ("receiver_binding", "claim", "trust", "status", "audience", "rate", "finalize", "progress", "evaluator")


@dataclass
class Counts:
    receiver_binding: int = 0
    claim: int = 0
    trust: int = 0
    status: int = 0
    audience: int = 0
    rate: int = 0
    finalize: int = 0
    progress: int = 0
    evaluator: int = 0

    def as_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}


def expected_counts(raw: dict) -> dict:
    return {name: int(raw.get(name, 0)) for name in COUNT_NAMES}


@dataclass
class KeyFixture:
    pub: dict
    id: dict
    seeds: dict

    def priv(self, name: str):
        return _private_key(name)


@lru_cache(maxsize=None)
def _private_key(name: str):
    from ratify_protocol_v2.signing_v2 import keypair_from_seeds_v2

    entry = next(k for k in load("keys.json")["keys"] if k["name"] == name)
    return keypair_from_seeds_v2(bytes.fromhex(entry["ed25519_seed_hex"]), bytes.fromhex(entry["ml_dsa_65_seed_hex"]))[1]


@lru_cache(maxsize=1)
def keys() -> KeyFixture:
    data = load("keys.json")
    pub = {k["name"]: pubkey(k["public_key"]) for k in data["keys"]}
    ids = {k["name"]: k["key_id_v2"] for k in data["keys"]}
    seeds = {k["name"]: (k["ed25519_seed_hex"], k["ml_dsa_65_seed_hex"]) for k in data["keys"]}
    return KeyFixture(pub=pub, id=ids, seeds=seeds)


def status_policy(raw: Optional[dict]):
    from ratify_protocol_v2.status_state_v2 import RevocationStatusPolicyV2

    raw = raw or {}
    return RevocationStatusPolicyV2(max_list_lifetime_seconds=raw.get("max_list_lifetime_seconds", 0),
                                    max_status_age_seconds=raw.get("max_status_age_seconds", 0),
                                    clock_skew_seconds=raw.get("clock_skew_seconds", 0))


class ScriptedClaimStore(ClaimStoreV2):
    """A single-claim scripted claim store (Go v2ScriptedClaimStore)."""

    def __init__(self, mode: str, claimed_at: int, finalization_at: int, counts: Counts):
        self.mode, self.claimed_at, self.finalization_at, self.counts = mode, claimed_at, finalization_at, counts
        self.final_body: Optional[bytes] = None
        self.expires_at = 0
        self.progress = None

    def authoritative_time_v2(self, ctx):
        return self.finalization_at

    def claim_v2(self, ctx, claim):
        self.counts.claim += 1
        self.expires_at = claim.expires_at
        if self.mode == "create":
            return V2ClaimResult(disposition=V2_CLAIM_CREATED, claimed_at=self.claimed_at, owner_token=bytes([7]) * 32)
        if self.mode == "proof_conflict":
            raise ClaimProofConflictError()
        if self.mode == "in_progress":
            return V2ClaimResult(disposition=V2_CLAIM_IN_PROGRESS, claimed_at=self.claimed_at)
        if self.mode == "terminal_replay":
            return V2ClaimResult(disposition=V2_CLAIM_TERMINAL_REPLAY, claimed_at=self.claimed_at)
        raise RuntimeError("scripted claim store unavailable")

    def finalize_v2_claim(self, ctx, claim_id, owner_token, terminal_result, receipt_body, allow_valid_until):
        self.counts.finalize += 1
        if self.finalization_at < self.claimed_at:
            raise V2Error(V2ErrorClass.CLOCK_REGRESSED, "scripted finalization clock regressed")
        if allow_valid_until > 0 and (self.finalization_at >= allow_valid_until or self.finalization_at >= self.expires_at):
            raise V2Error(V2ErrorClass.ALLOW_HORIZON_PASSED, "scripted allow at or beyond its deadline")
        self.final_body = bytes(receipt_body)
        return True

    def record_v2_evaluation_progress(self, ctx, claim_id, owner_token, progress):
        self.counts.progress += 1
        self.progress = progress

    def load_v2_interrupted_claim(self, ctx, claim_id):
        raise RuntimeError("not used by ordering vectors")

    def recover_interrupted_v2_claim(self, ctx, claim_id, terminal_result, receipt_body):
        raise RuntimeError("not used by ordering vectors")


class ScriptedRateStore(V2RateReservationStore):
    def __init__(self, mode: str, counts: Counts):
        self.mode, self.counts, self.batch = mode, counts, None

    def reserve_v2_rate_batch(self, ctx, claim_id, owner_token, bundle_hash, batch):
        from ratify_protocol_v2.rate_reservation_v2 import V2RateLimitExceededError

        self.counts.rate += 1
        self.batch = list(batch)
        if self.mode == "reserve":
            return None
        if self.mode == "exceeded":
            raise V2RateLimitExceededError()
        if self.mode == "panic":
            raise SystemError("scripted rate store panic")
        raise RuntimeError("scripted rate store unavailable")


class ModalJournalStore:
    """The reference journal with the scripted failure modes of the vectors."""

    def __init__(self, inner, mode: str):
        self.inner, self.mode, self.cas_calls = inner, mode, 0

    def load(self, ctx):
        from ratify_protocol_v2.security_journal_v2 import SecurityJournalHeadV2

        if self.mode == "load_error":
            raise RuntimeError("scripted journal load failure")
        journal, head = self.inner.load(ctx)
        if self.mode == "unanchored":
            head = SecurityJournalHeadV2(generation=head.generation, digest="e" * 96)
        return journal, head

    def compare_and_swap(self, ctx, head, nxt):
        from ratify_protocol_v2.security_journal_v2 import SecurityJournalConflictV2

        self.cas_calls += 1
        if self.mode == "cas_conflict" or (self.mode == "cas_conflict_once" and self.cas_calls % 2 == 1):
            raise SecurityJournalConflictV2()
        return self.inner.compare_and_swap(ctx, head, nxt)


def populate_status_journal(store, inputs: dict) -> None:
    """Go v2PopulateStatusJournal: configure status keys in ascending issuer
    order, then apply the journal preload; or, when journal.setup is present,
    exactly those steps in order."""
    from ratify_protocol_v2.protocol_v2 import decode_revocation_list_v2, decode_revocation_push_v2
    from ratify_protocol_v2.security_journal_v2 import (
        apply_revocation_list_to_journal_v2,
        apply_revocation_push_to_journal_v2,
        configure_status_key_epoch_v2,
    )

    policy = status_policy(inputs.get("status_policy"))

    def apply(issuer: str, code: int, wire_b64: str, epoch: int, key: dict, now: int) -> None:
        wire = b64(wire_b64)
        if code == 3:
            apply_revocation_list_to_journal_v2(BACKGROUND, store, decode_revocation_list_v2(wire), issuer, epoch,
                                                pubkey(key), policy, now)
        elif code == 5:
            apply_revocation_push_to_journal_v2(BACKGROUND, store, decode_revocation_push_v2(wire), issuer, epoch,
                                                pubkey(key), policy, now)
        else:
            raise AssertionError(f"unknown journal object type code {code}")

    setup = (inputs.get("journal") or {}).get("setup")
    if setup is not None:
        for step in setup:
            if step["op"] == "configure_status_key":
                configure_status_key_epoch_v2(BACKGROUND, store, step["issuer_id"], step["epoch"], pubkey(step["public_key"]))
            elif step["op"] == "apply":
                apply(step["issuer_id"], step["object_type_code"], step["wire_b64"], step["epoch"], step["public_key"],
                      step["now"])
            else:
                raise AssertionError(f"unknown journal setup op {step['op']!r}")
        return
    status_keys = inputs.get("status_keys") or {}
    for issuer in sorted(status_keys, key=lambda s: s.encode("utf-8")):
        key = status_keys[issuer]
        configure_status_key_epoch_v2(BACKGROUND, store, issuer, key["epoch"], pubkey(key["public_key"]))
    for p in (inputs.get("journal") or {}).get("preload") or []:
        key = status_keys[p["issuer_id"]]
        apply(p["issuer_id"], p["object_type_code"], p["wire_b64"], key["epoch"], key["public_key"], p["now"])


def build_status_journal(inputs: dict):
    from ratify_protocol_v2.v2reference.journal import JournalStore

    store = JournalStore()
    populate_status_journal(store, inputs)
    return store


def build_evaluator_registry(inputs: dict, counts: Counts):
    """Go v2BuildEvaluatorRegistry."""
    from ratify_protocol_v2 import constraint_evaluator_v2 as ce

    standard = {
        ce.PROFILE_MAX_COUNT_V2: ce.standard_max_count_evaluator_v2().evaluate,
        ce.PROFILE_ALLOWED_VALUES_V2: ce.standard_allowed_values_evaluator_v2().evaluate,
    }
    registrations = []
    for e in inputs["constraint_evaluators"]:
        impl_name = e["implementation"]
        if impl_name == "fault:error":
            def impl(ctx, inp):
                raise RuntimeError("scripted evaluator failure")
        elif impl_name == "fault:panic":
            def impl(ctx, inp):
                raise SystemError("scripted evaluator panic")
        elif impl_name == "fault:timeout":
            def impl(ctx, inp):
                ctx.wait()
                return ce.ConstraintEvaluationResultV2(outcome=ce.CONSTRAINT_OUTCOME_PASS_V2)
        elif impl_name == "fault:invalid_outcome":
            def impl(ctx, inp):
                return ce.ConstraintEvaluationResultV2(outcome="maybe")
        elif impl_name == "fault:pass_until":
            def impl(ctx, inp, valid_until=e.get("valid_until", 0)):
                return ce.ConstraintEvaluationResultV2(outcome=ce.CONSTRAINT_OUTCOME_PASS_V2, valid_until=valid_until)
        else:
            impl = standard[impl_name]

        def counted(ctx, inp, inner=impl):
            counts.evaluator += 1
            return inner(ctx, inp)

        registrations.append(ce.ConstraintEvaluatorRegistrationV2(
            descriptor=ce.ConstraintProfileDescriptorV2(profile=e["profile"], type=e["type"]), evaluate=counted))
    return ce.new_constraint_evaluator_registry_v2(1.0, *registrations)


def build_verify_request(inputs: dict, bundle: Optional[bytes], counts: Counts):
    """Go v2BuildVerifyRequest: request and callbacks; the caller supplies the
    claim store. Returns (request, callbacks, rate_store)."""
    from ratify_protocol_v2.audience_v2 import V2AudienceMembership
    from ratify_protocol_v2.constraints_v2 import ConstraintContextV2
    from ratify_protocol_v2.context_policy_v2 import new_v2_context_policy
    from ratify_protocol_v2.status_batch_v2 import V2StatusEvidenceBatch, V2StatusEvidenceObject
    from ratify_protocol_v2.status_provenance_v2 import V2StatusKeyConfig

    req = V2VerifyRequest(
        bundle=bundle or b"", required_scope=inputs.get("required_scope", ""),
        verifier_namespace=inputs.get("configured_namespace", ""), replay_epoch=inputs.get("configured_replay_epoch", 0),
        verifier_id=inputs.get("configured_verifier_id", ""), now=inputs.get("now", 0), max_challenge_age_seconds=inputs.get("max_challenge_age_seconds", 0),
        future_skew_seconds=inputs.get("future_skew_seconds", 0), status_policy=status_policy(inputs.get("status_policy")),
        status_keys={}, tzdb_version=inputs.get("tzdb_version", ""), context=ConstraintContextV2(),
    )
    for issuer, key in (inputs.get("status_keys") or {}).items():
        req.status_keys[issuer] = V2StatusKeyConfig(epoch=key["epoch"], key=pubkey(key["public_key"]))
    e = inputs.get("expected_challenge")
    if e is not None:
        exp = ExpectedChallengeV2(value=b64(e["value_b64"]), issued_at=e["issued_at"], expires_at=e["expires_at"],
                                  verifier_namespace=e["verifier_namespace"], replay_epoch=e["replay_epoch"],
                                  verifier_id=e["verifier_id"])
        # The agent ID and key pass through independently, so a vector can
        # configure either one alone (SPEC-v2 §6.2 step 7).
        if e.get("expected_agent_id") is not None:
            exp.expected_agent_id = e["expected_agent_id"]
        if e.get("expected_agent_public_key") is not None:
            exp.expected_agent_public_key = pubkey(e["expected_agent_public_key"])
        if e.get("expected_receiver_id") is not None:
            exp.expected_receiver_id = e["expected_receiver_id"]
        if e.get("expected_session_context_b64") is not None:
            exp.expected_session_context = b64(e["expected_session_context_b64"])
        req.expected = exp
    p = inputs.get("context_policy")
    if p is not None:
        expected = b64(p["expected_session_context_b64"]) if p.get("expected_session_context_b64") is not None else None
        req.context_policy = new_v2_context_policy(p["profile"], p["require_bound"], list(p.get("required_fields") or []), expected)
    c = inputs.get("request_context")
    if c is not None:
        req.context = ConstraintContextV2(
            has_resource=c.get("has_resource", False), requested_resource_id=c.get("requested_resource_id", ""),
            requested_path=c.get("requested_path", ""), has_amount=c.get("has_amount", False),
            requested_amount_micros=c.get("requested_amount_micros", 0), requested_currency=c.get("requested_currency", ""),
            extension_counts=c.get("extension_counts"), extension_values=c.get("extension_values"))
    if inputs.get("constraint_evaluators"):
        req.constraint_evaluators = build_evaluator_registry(inputs, counts)

    trust_in = inputs.get("trust")
    registry = None
    if trust_in is not None and trust_in.get("mode") == "registry":
        registry = TrustRegistry([pubkey(k) for k in trust_in.get("registry") or []])

    def trust(ctx, chain):
        counts.trust += 1
        if trust_in is None:
            return V2TrustResolution(outcome="unavailable")
        if trust_in.get("mode") == "registry":
            return registry.resolve(ctx, chain)
        if trust_in.get("mode") == "error":
            raise RuntimeError("scripted trust provider failure")
        if trust_in.get("mode") == "panic":
            raise SystemError("scripted trust provider panic")
        out = V2TrustResolution(outcome=trust_in.get("outcome", ""))
        if trust_in.get("root_public_key") is not None:
            out.root_key = pubkey(trust_in["root_public_key"])
        return out

    evidence_in = inputs.get("status_evidence") or {}

    def status_evidence(ctx, r):
        counts.status += 1
        script = evidence_in.get(r.issuer_id)
        if script is None:
            return V2StatusEvidenceBatch(objects=[])
        if script.get("mode") == "error":
            raise RuntimeError("scripted status provider failure")
        if script.get("mode") == "panic":
            raise SystemError("scripted status provider panic")
        return V2StatusEvidenceBatch(objects=[V2StatusEvidenceObject(object_type=o["object_type_code"], wire=b64(o["wire_b64"]))
                                              for o in script.get("objects") or []])

    audience_mode = inputs.get("audience_mode", "")
    memberships_in = inputs.get("audience_memberships") or []

    def audience(ctx, deferred, receiver_id):
        counts.audience += 1
        if audience_mode == "error":
            raise RuntimeError("scripted audience provider failure")
        if audience_mode == "panic":
            raise SystemError("scripted audience provider panic")
        return [V2AudienceMembership(delegation_index=m["delegation_index"], constraint_index=m["constraint_index"],
                                     receiver_id=m["receiver_id"], trust_domain_ids=list(m.get("trust_domain_ids") or []),
                                     issued_at=m["issued_at"], expires_at=m["expires_at"], evidence_digest=m["evidence_digest"])
                for m in memberships_in]

    cb = V2VerifyCallbacks(trust=trust, status_evidence=status_evidence, audience=audience)
    journal_mode = (inputs.get("journal") or {}).get("mode", "")
    if journal_mode != "absent":
        cb.status_journal = ModalJournalStore(build_status_journal(inputs), journal_mode)
    hook_mode = inputs.get("receiver_binding_hook", "")
    if hook_mode in ("accept", "reject"):
        def hook(bundle_obj, expected):
            counts.receiver_binding += 1
            if hook_mode == "reject":
                raise RuntimeError("application receiver binding rejected")
        cb.receiver_binding = hook
    rate = None
    rate_mode = inputs.get("rate", "")
    if rate_mode not in ("absent", ""):
        rate = ScriptedRateStore(rate_mode, counts)
        cb.rate = rate
    return req, cb, rate


class FixedClock:
    def __init__(self, now: int):
        self.now = now

    def authoritative_time_v2(self, ctx):
        return self.now


def keyed_claim(claim, label: str):
    """Give a hand-built test claim the challenge digest of ``label`` and the
    claim ID derived from its replay key (SPEC-v2 §2.4); the reference store
    refuses any other ID (§7.3)."""
    import dataclasses
    import hashlib

    from ratify_protocol_v2.challenge_claim_v2 import protocol_claim_id_from_digest_v2

    digest = hashlib.sha384(label.encode()).digest()
    return dataclasses.replace(claim, challenge_digest="sha384:" + digest.hex(),
                               claim_id=protocol_claim_id_from_digest_v2(claim.namespace, claim.replay_epoch, digest))
