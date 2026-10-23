"""Challenge issuance containment: a random source or issuance store that
raises any BaseException is handled exactly as one that raises an Exception,
as Go recovers a panic at the same call sites. KeyboardInterrupt and
SystemExit are the caller's own cancellation and propagate."""
from __future__ import annotations

import pytest

from v2_harness import BACKGROUND, keys

from ratify_protocol_v2 import _native
from ratify_protocol_v2.challenge_issuance_v2 import (
    V2ChallengeIssuer,
    V2ChallengeIssueRequest,
    load_expected_challenge_v2,
)
from ratify_protocol_v2.errors_v2 import V2ErrorClass, error_class_of
from ratify_protocol_v2.v2reference.challenges import TestOnlyChallengeIssuanceStore
from ratify_protocol_v2.v2reference.store import Store

pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="the reference store signs receipts; signing needs ratify-protocol-native-v2")


class StoreFailure(BaseException):
    """Not an Exception: the Python counterpart of a Go panic."""


FAILURES = [RuntimeError, StoreFailure]
CANCELLATIONS = [KeyboardInterrupt, SystemExit]


def raising(exc_type):
    def fn(*_args, **_kwargs):
        raise exc_type("injected")
    return fn


def issuer(**overrides):
    fx = keys()
    clock = Store(1800000000, 60, "0123456789abcdef0123456789abcdef", fx.priv("verifier"))
    parts = {"clock": clock, "store": TestOnlyChallengeIssuanceStore(), "random": lambda n: b"\x07" * n}
    parts.update(overrides)
    return V2ChallengeIssuer(**parts), V2ChallengeIssueRequest(
        verifier_namespace="ns", replay_epoch=1, verifier_id=fx.id["verifier"], lifetime_seconds=60)


@pytest.mark.parametrize("exc_type", FAILURES)
def test_random_source_failure_is_configuration_invalid(exc_type):
    iss, req = issuer(random=raising(exc_type))
    with pytest.raises(Exception) as err:
        iss.issue_challenge_v2(BACKGROUND, req)
    assert error_class_of(err.value) == V2ErrorClass.CONFIGURATION_INVALID


@pytest.mark.parametrize("exc_type", FAILURES)
def test_persist_failure_is_claim_store_unavailable(exc_type):
    store = TestOnlyChallengeIssuanceStore()
    store.persist_v2_challenge = raising(exc_type)
    iss, req = issuer(store=store)
    with pytest.raises(Exception) as err:
        iss.issue_challenge_v2(BACKGROUND, req)
    assert error_class_of(err.value) == V2ErrorClass.CLAIM_STORE_UNAVAILABLE


@pytest.mark.parametrize("exc_type", FAILURES)
def test_load_failure_is_expected_challenge_missing(exc_type):
    store = TestOnlyChallengeIssuanceStore()
    store.load_v2_challenge = raising(exc_type)
    with pytest.raises(Exception) as err:
        load_expected_challenge_v2(BACKGROUND, store, "ns", 1, b"\x07" * 32)
    assert error_class_of(err.value) == V2ErrorClass.EXPECTED_CHALLENGE_MISSING


@pytest.mark.parametrize("exc_type", CANCELLATIONS)
def test_cancellation_propagates(exc_type):
    iss, req = issuer(random=raising(exc_type))
    with pytest.raises(exc_type):
        iss.issue_challenge_v2(BACKGROUND, req)
    store = TestOnlyChallengeIssuanceStore()
    store.persist_v2_challenge = raising(exc_type)
    iss, req = issuer(store=store)
    with pytest.raises(exc_type):
        iss.issue_challenge_v2(BACKGROUND, req)
    store = TestOnlyChallengeIssuanceStore()
    store.load_v2_challenge = raising(exc_type)
    with pytest.raises(exc_type):
        load_expected_challenge_v2(BACKGROUND, store, "ns", 1, b"\x07" * 32)
