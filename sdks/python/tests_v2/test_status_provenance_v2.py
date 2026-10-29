"""Unit tests for the authenticated status stage (SPEC-v2 §6.5).

A provider exception, a journal failure, an unauthenticated batch, and a
second compare-and-swap conflict all make the issuer unavailable with no
evidence; one conflict is retried exactly once without a second provider
call; cancellation is reported, not converted into a status result.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from corpus import b64, load, pubkey
from ratify_protocol.v2 import context_v2
from ratify_protocol.v2 import security_journal_v2 as sj
from ratify_protocol.v2.status_provenance_v2 import V2StatusKeyConfig, run_v2_status_stage
from ratify_protocol.v2.status_state_v2 import RevocationStatusPolicyV2
from ratify_protocol.v2.v2reference.journal import JournalStore

KEYS = {k["name"]: k for k in load("keys.json")["keys"]}
SEQ = load("status-sequences.json")["scenarios"][0]
LIST_WIRE = b64(SEQ["steps"][0]["wire_b64"])  # sequence 1 list revoking c1, signed by status_root
NOW = 1800000000
POLICY = RevocationStatusPolicyV2(3600, 600, 5)
CTX = context_v2.background()


def _pub(name):
    return pubkey(KEYS[name]["public_key"])


ROOT_ID = KEYS["root"]["key_id_v2"]
AGENT_ID = KEYS["agent"]["key_id_v2"]


def _bundle():
    cert = SimpleNamespace(issuer_pub_key=_pub("root"), subject_pub_key=_pub("agent"))
    return SimpleNamespace(agent_pub_key=_pub("agent"), delegations=[cert], verifier_id=KEYS["verifier"]["key_id_v2"])


def _checks(cert_id="c2"):
    # The verifier's V2CertificateStatusCheck; the stage reads only these members.
    return [SimpleNamespace(delegation_index=0, issuer_id=ROOT_ID, subject_id=AGENT_ID, cert_id=cert_id)]


def _batch(*wires):
    return SimpleNamespace(objects=[SimpleNamespace(object_type=3, wire=w) for w in wires])


def _store():
    store = JournalStore()
    sj.configure_status_key_epoch_v2(CTX, store, ROOT_ID, 1, _pub("status_root"))
    return store


def _req():
    return SimpleNamespace(status_keys={ROOT_ID: V2StatusKeyConfig(epoch=1, key=_pub("status_root"))}, status_policy=POLICY)


def _run(provider, store=None, ctx=CTX, cert_id="c2"):
    cb = SimpleNamespace(status_evidence=provider, status_journal=store if store is not None else _store())
    return run_v2_status_stage(ctx, _bundle(), _checks(cert_id), _req(), cb, NOW)


def test_current_status_from_an_authenticated_batch():
    stage = _run(lambda ctx, req: _batch(LIST_WIRE))
    assert stage.cancelled is None and stage.queries == 1
    assert stage.assessment.assessment == "current"
    assert stage.assessment.fresh_until > NOW
    assert [e.object_type for e in stage.assessment.evidence] == [3]


def test_revoked_reference():
    stage = _run(lambda ctx, req: _batch(LIST_WIRE), cert_id="c1")
    assert (stage.assessment.assessment, stage.assessment.reason) == ("revoked", "delegation_revoked")


@pytest.mark.parametrize("exc", [RuntimeError("provider down"), ValueError("bad"), KeyError("x"), ZeroDivisionError()])
def test_provider_exception_is_unavailable(exc):
    def provider(ctx, req):
        raise exc

    stage = _run(provider)
    assert stage.cancelled is None and stage.queries == 1
    assert (stage.assessment.assessment, stage.assessment.reason) == ("unavailable", "status_unavailable")
    assert stage.assessment.evidence == []


def test_provider_returning_garbage_is_unavailable():
    for bad in (None, "batch", SimpleNamespace(objects="x"), _batch(b"{}"), SimpleNamespace(objects=[SimpleNamespace(object_type=4, wire=LIST_WIRE)])):
        stage = _run(lambda ctx, req, bad=bad: bad)
        assert stage.assessment.assessment == "unavailable"


def test_unauthenticated_batch_is_unavailable():
    tampered = bytearray(LIST_WIRE)
    i = tampered.index(b'"sequence":1')
    tampered[i + len(b'"sequence":')] = ord("2")
    stage = _run(lambda ctx, req: _batch(bytes(tampered)))
    assert stage.assessment.assessment == "unavailable"


def test_provider_receives_the_issuer_request():
    seen = []

    def provider(ctx, req):
        seen.append(req)
        return _batch(LIST_WIRE)

    _run(provider)
    (req,) = seen
    assert (req.issuer_id, req.status_key_epoch, req.status_key_id) == (ROOT_ID, 1, KEYS["status_root"]["key_id_v2"])
    assert [(r.issuer_id, r.cert_id) for r in req.refs] == [(ROOT_ID, "c2")]


class ConflictingStore:
    """Wraps the reference store; the first ``conflicts`` compare-and-swap
    calls fail as a stale writer would."""

    def __init__(self, inner, conflicts):
        self.inner, self.conflicts, self.cas_calls, self.loads = inner, conflicts, 0, 0

    def load(self, ctx):
        self.loads += 1
        return self.inner.load(ctx)

    def compare_and_swap(self, ctx, expected, nxt):
        self.cas_calls += 1
        if self.cas_calls <= self.conflicts:
            raise sj.SecurityJournalConflictV2()
        return self.inner.compare_and_swap(ctx, expected, nxt)


def test_one_conflict_is_retried_once_without_a_second_provider_call():
    calls = []
    store = ConflictingStore(_store(), conflicts=1)
    stage = _run(lambda ctx, req: calls.append(1) or _batch(LIST_WIRE), store=store)
    assert stage.assessment.assessment == "current"
    assert len(calls) == 1 and store.cas_calls == 2 and store.loads == 2


def test_second_conflict_is_unavailable():
    store = ConflictingStore(_store(), conflicts=2)
    stage = _run(lambda ctx, req: _batch(LIST_WIRE), store=store)
    assert stage.assessment.assessment == "unavailable"
    assert store.cas_calls == 2


def test_journal_load_failure_is_unavailable_without_a_provider_call():
    class Broken:
        def load(self, ctx):
            raise OSError("disk")

    calls = []
    stage = _run(lambda ctx, req: calls.append(1), store=Broken())
    assert stage.assessment.assessment == "unavailable" and calls == [] and stage.queries == 0


def test_cancellation_is_reported():
    ctx = context_v2.with_cancel(context_v2.background())

    def provider(c, req):
        ctx.cancel()
        raise RuntimeError("cancelled mid-call")

    stage = _run(provider, ctx=ctx)
    assert isinstance(stage.cancelled, context_v2.Cancelled)


def test_status_key_equal_to_a_proof_key_is_unavailable():
    store = JournalStore()
    sj.configure_status_key_epoch_v2(CTX, store, ROOT_ID, 1, _pub("agent"))
    req = SimpleNamespace(status_keys={ROOT_ID: V2StatusKeyConfig(epoch=1, key=_pub("agent"))}, status_policy=POLICY)
    cb = SimpleNamespace(status_evidence=lambda ctx, r: _batch(LIST_WIRE), status_journal=store)
    stage = run_v2_status_stage(CTX, _bundle(), _checks(), req, cb, NOW)
    assert stage.assessment.assessment == "unavailable" and stage.queries == 0


def test_concurrent_stages_on_one_store_converge():
    store = _store()
    results = []

    def worker():
        results.append(_run(lambda ctx, req: _batch(LIST_WIRE), store=store).assessment.assessment)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == ["current"] * 8
    assert store.head().generation == 2  # configure + one effective application
