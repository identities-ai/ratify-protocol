"""The boundary this reference exists to hold.

Each test breaks exactly one thing and asserts the protected handler did not
run. None of them need AWS: the authority decision is independent of which
runtime hosts the two agents.
"""
from __future__ import annotations

import time
import uuid

import pytest
from ratify_protocol import decode_proof_bundle, encode_proof_bundle

from bedrock_ratify.config import RESOURCE_ID
from bedrock_ratify.identity import build_cast, issue_directory_delegation
from bedrock_ratify.presenter import build_proof
from bedrock_ratify.receiver import DirectoryRequest, SideEventsCustodian


@pytest.fixture
def cast():
    return build_cast()


@pytest.fixture
def custodian(cast):
    return SideEventsCustodian(verifier=cast.agent2, trusted_root_id=cast.principal.id)


def request_for(path="/", resource=RESOURCE_ID):
    return DirectoryRequest(
        session_id="test-session",
        invocation_id=f"inv-{uuid.uuid4()}",
        resource_id=resource,
        path=path,
    )


def present(custodian, cast, chain, req, mutate=None):
    challenge, ctx = custodian.issue_challenge(req, cast.agent1.id)
    bundle = build_proof(cast.agent1, chain, challenge, ctx)
    if mutate:
        bundle = mutate(bundle)
    return custodian.list_directory(req, bundle)


def read_grant(cast, **kw):
    return [issue_directory_delegation(cast.principal, cast.agent1,
                                       scopes=["files:read"], **kw)]


# -- the one thing that must work -------------------------------------------


def test_authorized_request_reaches_the_handler(custodian, cast):
    decision = present(custodian, cast, read_grant(cast), request_for("/"))
    assert decision.allowed, decision.reason
    assert custodian.handler_invocations == 1
    assert {e["name"] for e in decision.entries}
    assert decision.receipt_hash_b64


def test_receipt_verifies_and_chains(custodian, cast):
    from ratify_protocol import decode_verification_receipt, verify_verification_receipt

    first = present(custodian, cast, read_grant(cast), request_for("/"))
    second = present(custodian, cast, read_grant(cast), request_for("/"))
    for decision in (first, second):
        receipt = decode_verification_receipt(decision.receipt_b64)
        assert verify_verification_receipt(receipt) is None
    later = decode_verification_receipt(second.receipt_b64)
    assert later.prev_hash, "second receipt must chain to the first"


# -- the eight ways it must not ---------------------------------------------


def test_path_outside_the_granted_prefix_is_refused(custodian, cast):
    chain = read_grant(cast, path_prefix="/tools")
    decision = present(custodian, cast, chain, request_for("/"))
    assert not decision.allowed
    assert "resource_path" in decision.reason
    assert custodian.handler_invocations == 0


def test_subdirectory_inside_the_granted_prefix_is_allowed(custodian, cast):
    chain = read_grant(cast, path_prefix="/tools")
    decision = present(custodian, cast, chain, request_for("/tools"))
    assert decision.allowed, decision.reason


def test_other_resource_is_refused(custodian, cast):
    decision = present(custodian, cast, read_grant(cast),
                       request_for("/", resource="file:payroll"))
    assert not decision.allowed
    assert custodian.handler_invocations == 0


def test_undelegated_scope_is_refused(custodian, cast):
    chain = [issue_directory_delegation(cast.principal, cast.agent1,
                                        scopes=["files:write"])]
    decision = present(custodian, cast, chain, request_for("/"))
    assert not decision.allowed
    assert "scope_denied" in decision.reason


def test_untrusted_principal_is_refused(custodian, cast):
    chain = [issue_directory_delegation(cast.stranger, cast.agent1,
                                        scopes=["files:read"])]
    decision = present(custodian, cast, chain, request_for("/"))
    assert not decision.allowed
    assert "untrusted_root" in decision.reason
    assert custodian.handler_invocations == 0


def test_expired_delegation_is_refused(custodian, cast):
    chain = read_grant(cast, now=int(time.time()) - 7200, ttl_seconds=3600)
    decision = present(custodian, cast, chain, request_for("/"))
    assert not decision.allowed
    assert "expired" in decision.reason


def test_scope_widened_after_signing_is_refused(custodian, cast):
    def widen(bundle):
        cloned = decode_proof_bundle(encode_proof_bundle(bundle))
        cloned.delegations[0].scope = sorted(
            set(cloned.delegations[0].scope) | {"data:export"}
        )
        return cloned

    decision = present(custodian, cast, read_grant(cast), request_for("/"), mutate=widen)
    assert not decision.allowed
    assert "signature" in decision.reason


def test_replayed_challenge_is_refused(custodian, cast):
    chain = read_grant(cast)
    req = request_for("/")
    challenge, ctx = custodian.issue_challenge(req, cast.agent1.id)
    bundle = build_proof(cast.agent1, chain, challenge, ctx)
    assert custodian.list_directory(req, bundle).allowed
    replay = custodian.list_directory(req, bundle)
    assert not replay.allowed
    assert "challenge" in replay.reason
    assert custodian.handler_invocations == 1


def test_revocation_beats_remaining_validity(custodian, cast):
    chain = read_grant(cast)
    assert present(custodian, cast, chain, request_for("/")).allowed
    remaining = chain[0].expires_at - int(time.time())
    assert remaining > 3000, "the certificate must still be far from expiry"
    custodian.revoke(chain[0].cert_id)
    decision = present(custodian, cast, chain, request_for("/"))
    assert not decision.allowed
    assert "revoked" in decision.reason
    assert custodian.handler_invocations == 1


# -- narrowing ---------------------------------------------------------------


def test_subdelegation_cannot_grow_authority(cast):
    parent = issue_directory_delegation(cast.principal, cast.agent1,
                                        scopes=["files:read", "identity:delegate"])
    child = issue_directory_delegation(cast.agent1, cast.agent2,
                                       scopes=["files:read"], parent=parent,
                                       ttl_seconds=10 * parent.expires_at)
    assert child.scope == ["files:read"]
    assert child.expires_at <= parent.expires_at

    with pytest.raises(ValueError):
        issue_directory_delegation(cast.agent1, cast.agent2,
                                   scopes=["payments:send"], parent=parent)
