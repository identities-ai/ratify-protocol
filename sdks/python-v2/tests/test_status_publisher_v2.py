"""Signed-status publisher scenarios (testvectors/v2/status-publisher.json).

The publisher is built from the anchored role journal; every published object
must verify under the status key with the typed revocation verifiers and
carry exactly the expected signed fields; the same journal ingests the
objects and must report the expected status. Every role-configuration
refusal must be configuration_invalid with no object signed.
"""
from __future__ import annotations

import pytest

from corpus import load, pubkey
from ratify_protocol_v2 import context_v2
from ratify_protocol_v2 import security_journal_v2 as sj
from ratify_protocol_v2 import status_publisher_v2 as sp
from ratify_protocol_v2.errors_v2 import error_class_of
from ratify_protocol_v2.protocol_v2 import verify_revocation_list_v2_signature, verify_revocation_push_v2_signature
from ratify_protocol_v2.signing_v2 import key_id_v2, keypair_from_seeds_v2, _new_local_signer_v2
from ratify_protocol_v2.status_state_v2 import RevocationStatusPolicyV2, revoked_cert_ids_v2
from ratify_protocol_v2.v2reference.journal import JournalStore

from ratify_protocol_v2 import _native  # noqa: E402

pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="the status publisher signs; signing needs ratify-protocol-native-v2")

VECTORS = load("status-publisher.json")
KEYS = {k["name"]: k for k in load("keys.json")["keys"]}
CTX = context_v2.background()
POLICY = RevocationStatusPolicyV2(**VECTORS["status_policy"])


def _pub(name):
    return pubkey(KEYS[name]["public_key"])


def _private(name):
    entry = KEYS[name]
    return keypair_from_seeds_v2(bytes.fromhex(entry["ed25519_seed_hex"]), bytes.fromhex(entry["ml_dsa_65_seed_hex"]))[1]


class CountingSigner:
    """A direct-mode signer that counts calls, to prove refusals sign nothing."""

    def __init__(self, name):
        self._inner = _new_local_signer_v2(_private(name))
        self.calls = 0

    def public_key_v2(self):
        return self._inner.public_key_v2()

    def mode_v2(self):
        return self._inner.mode_v2()

    def sign_v2(self, ctx, req):
        self.calls += 1
        return self._inner.sign_v2(ctx, req)


def _setup(sc):
    store = JournalStore()
    for entry in sc["role_keys"]:
        sj.record_security_key_role_v2(CTX, store, entry["role"], _pub(entry["key"]))
    outcome = "not_configured"
    if sc["status_configured_for"]:
        issuer_id = key_id_v2(_pub(sc["status_configured_for"]))
        try:
            sj.configure_status_key_epoch_v2(CTX, store, issuer_id, 1, _pub(sc["status_key"]))
            outcome = "configured"
        except Exception:  # noqa: BLE001 - the vector names only the outcome
            outcome = "rejected"
    return store, outcome


def _check_list(lst, want, issuer_id, status_pub):
    verify_revocation_list_v2_signature(lst, issuer_id, status_pub)
    assert (lst.sequence, lst.updated_at, lst.next_update, revoked_cert_ids_v2(lst.revoked)) == (
        want["sequence"], want["updated_at"], want["next_update"], want["revoked"])


def _check_push(push, want, issuer_id, status_pub):
    verify_revocation_push_v2_signature(push, issuer_id, status_pub)
    assert (push.sequence, push.pushed_at, revoked_cert_ids_v2(push.revoked)) == (
        want["sequence"], want["pushed_at"], want["revoked"])


def test_counts():
    assert len(VECTORS["scenarios"]) == 13
    assert sum(len(s["steps"]) for s in VECTORS["scenarios"]) == 39


@pytest.mark.parametrize("sc", VECTORS["scenarios"], ids=lambda s: s["name"])
def test_status_publisher_scenario(sc):
    store, outcome = _setup(sc)
    assert outcome == sc["journal_setup"]
    signer = CountingSigner(sc["status_key"])
    issuer_pub = _pub(sc["issuer"])
    issuer_id = key_id_v2(issuer_pub)
    status_pub = _pub(sc["status_key"])
    if sc["publisher"] == "refused":
        with pytest.raises(Exception) as excinfo:
            sp.new_v2_status_publisher(CTX, store, issuer_pub, signer, sc["lifetime_seconds"])
        assert error_class_of(excinfo.value) == "configuration_invalid"
        assert signer.calls == 0
        # The in-process key path applies the same role checks.
        with pytest.raises(Exception) as excinfo:
            sp.new_v2_status_publisher_with_key(CTX, store, issuer_pub, _private(sc["status_key"]), sc["lifetime_seconds"])
        assert error_class_of(excinfo.value) == "configuration_invalid"
        assert not sc["steps"]
        return
    publisher = sp.new_v2_status_publisher(CTX, store, issuer_pub, signer, sc["lifetime_seconds"])
    assert publisher.issuer_id() == issuer_id
    assert publisher.status_key() == status_pub
    keyed = sp.new_v2_status_publisher_with_key(CTX, store, issuer_pub, _private(sc["status_key"]), sc["lifetime_seconds"])
    assert (keyed.issuer_id(), keyed.status_key()) == (issuer_id, status_pub)
    state = None
    publications = []
    for i, step in enumerate(sc["steps"]):
        op, want = step["op"], step["expect"]
        if op in ("genesis", "heartbeat", "revoke"):
            calls_before = signer.calls
            try:
                if op == "genesis":
                    out = publisher.genesis(CTX, step["at"])
                elif op == "heartbeat":
                    out = publisher.heartbeat(CTX, state, step["at"])
                else:
                    out = publisher.revoke(CTX, state, step.get("cert_ids", []), step["at"])
            except Exception:  # noqa: BLE001
                assert want["result"] == "refused", f"step {i}"
                assert signer.calls == calls_before, f"step {i}: a refusal signed"
                continue
            assert want["result"] == "published", f"step {i}"
            _check_list(out.list, want["list"], issuer_id, status_pub)
            if "push" in want:
                _check_push(out.push, want["push"], issuer_id, status_pub)
            else:
                assert out.push is None
            state = out.state
            publications.append(out)
        elif op == "ingest":
            pub = publications[step["publication"]]
            if step["object"] == "list":
                sj.apply_revocation_list_to_journal_v2(CTX, store, pub.list, issuer_id, 1, status_pub, POLICY, step["at"])
            else:
                sj.apply_revocation_push_to_journal_v2(CTX, store, pub.push, issuer_id, 1, status_pub, POLICY, step["at"])
            assert want["result"] == "applied"
        elif op == "status":
            result = sj.revocation_status_from_journal_v2(CTX, store, issuer_id, step["cert_id"], 1, status_pub, POLICY, step["at"])
            assert (result.status, result.reason) == (want["status"], want.get("reason", "")), f"step {i}"
        else:
            raise AssertionError(f"unknown op {op}")


def test_publisher_has_no_public_constructor():
    with pytest.raises(TypeError):
        sp.V2StatusPublisher(_token=object(), issuer_id="", status_key=None, status_key_id="", signer=None, lifetime=1)


@pytest.mark.parametrize("lifetime", [0, 86401, True, 1.5])
def test_lifetime_bounds(lifetime):
    store, _ = _setup(VECTORS["scenarios"][0])
    with pytest.raises(Exception) as excinfo:
        sp.new_v2_status_publisher(CTX, store, _pub("root"), CountingSigner("status_root"), lifetime)
    assert error_class_of(excinfo.value) == "configuration_invalid"
