"""Operation-context / session-context construction tests (SPEC §6.4.9).

The known-answer hex values are duplicated across all five SDK test
suites so the implementations provably produce byte-identical hashes."""
from __future__ import annotations

import pytest

from ratify_protocol import (
    OperationContext,
    SessionContextInputs,
    build_session_context,
    operation_context_hash,
)

KAT_EMPTY_OPERATION_HASH = "d135e239f4a5a5a0ad6385b204d6c81f3c10e6b2f5debfa3cc8079488970f82f"
KAT_FULL_OPERATION_HASH = "6b70b5f404f61624ab2379fee2756639d8629141ecb3593b53e5a22346e0c3e5"
KAT_SESSION_CONTEXT = "788c692b5dafae52dd896eb5f7580f61d42b8c7a2abeed4d4eea9dcd4d7d4dfd"


def _full_operation() -> OperationContext:
    return OperationContext(
        required_scope="files:write",
        operation="git.push",
        resource_id="git:github.com/acme/api",
        requested_path="/src/handlers",
        payload_digest=b"\xab" * 32,
    )


def test_known_answers_match_the_go_reference():
    assert operation_context_hash(OperationContext()).hex() == KAT_EMPTY_OPERATION_HASH
    assert operation_context_hash(_full_operation()).hex() == KAT_FULL_OPERATION_HASH

    session = build_session_context(
        SessionContextInputs(
            verifier_id="verifier-1",
            workspace_id="ws-42",
            agent_id="agent-7",
            session_id="sess-9",
            invocation_id="inv-3",
            request_hash=operation_context_hash(_full_operation()),
        )
    )
    assert len(session) == 32
    assert session.hex() == KAT_SESSION_CONTEXT


def test_length_prefixing_disambiguates_shifted_boundaries():
    a = operation_context_hash(OperationContext(operation="ab", resource_id="c"))
    b = operation_context_hash(OperationContext(operation="a", resource_id="bc"))
    assert a != b


def test_domain_separation_between_the_two_constructions():
    op_hash = operation_context_hash(OperationContext())
    session = build_session_context(SessionContextInputs(request_hash=op_hash))
    assert op_hash != session


def test_input_validation():
    with pytest.raises(ValueError, match="payload digest"):
        operation_context_hash(OperationContext(payload_digest=b"\x00" * 5))
    with pytest.raises(ValueError, match="request hash"):
        build_session_context(SessionContextInputs(request_hash=b"\x00" * 16))
    with pytest.raises(ValueError, match="request hash"):
        build_session_context(SessionContextInputs())


def test_every_field_is_load_bearing():
    base = operation_context_hash(_full_operation())
    for mutated in (
        OperationContext(**{**_full_operation().__dict__, "required_scope": "files:read"}),
        OperationContext(**{**_full_operation().__dict__, "operation": "git.pull"}),
        OperationContext(**{**_full_operation().__dict__, "resource_id": "git:github.com/acme/api2"}),
        OperationContext(**{**_full_operation().__dict__, "requested_path": "/src"}),
        OperationContext(**{**_full_operation().__dict__, "payload_digest": b"\xac" * 32}),
    ):
        assert operation_context_hash(mutated) != base

    request_hash = operation_context_hash(_full_operation())
    session_base = SessionContextInputs(
        verifier_id="verifier-1",
        workspace_id="ws-42",
        agent_id="agent-7",
        session_id="sess-9",
        invocation_id="inv-3",
        request_hash=request_hash,
    )
    base_session = build_session_context(session_base)
    other_hash = operation_context_hash(OperationContext(operation="other"))
    for mutated in (
        SessionContextInputs(**{**session_base.__dict__, "verifier_id": "verifier-2"}),
        SessionContextInputs(**{**session_base.__dict__, "workspace_id": "ws-43"}),
        SessionContextInputs(**{**session_base.__dict__, "agent_id": "agent-8"}),
        SessionContextInputs(**{**session_base.__dict__, "session_id": "sess-10"}),
        SessionContextInputs(**{**session_base.__dict__, "invocation_id": "inv-4"}),
        SessionContextInputs(**{**session_base.__dict__, "request_hash": other_hash}),
    ):
        assert build_session_context(mutated) != base_session


def test_ill_formed_unicode_is_rejected_not_replaced():
    # A Python str can carry lone surrogates (e.g. from surrogateescape
    # decoding); §6.4.9 requires rejecting ill-formed text explicitly.
    bad = "\ud800x"
    for ctx in (
        OperationContext(required_scope=bad),
        OperationContext(operation=bad),
        OperationContext(resource_id=bad),
        OperationContext(requested_path=bad),
    ):
        with pytest.raises(ValueError, match="well-formed Unicode"):
            operation_context_hash(ctx)

    valid_hash = operation_context_hash(OperationContext())
    for inputs in (
        SessionContextInputs(verifier_id=bad, request_hash=valid_hash),
        SessionContextInputs(workspace_id=bad, request_hash=valid_hash),
        SessionContextInputs(agent_id=bad, request_hash=valid_hash),
        SessionContextInputs(session_id=bad, request_hash=valid_hash),
        SessionContextInputs(invocation_id=bad, request_hash=valid_hash),
    ):
        with pytest.raises(ValueError, match="well-formed Unicode"):
            build_session_context(inputs)

    # Astral characters (valid non-BMP text) are fine.
    assert len(operation_context_hash(OperationContext(operation="\U0001F600"))) == 32
