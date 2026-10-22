"""Dual-root composition profile (mirrors Go v2reference/approval_ledger.go,
SPEC-v2 §7.14), TEST ONLY.

An approval set names one action through its authenticated fields. The
ledger derives the expected session context from them with invocation_id =
approval_set_id (SPEC-v2 §2.4) and never accepts a caller-supplied context.
It marks the action executable only when both released allows match the set
and are still within their deadlines, executes it exactly once, and refuses
to count one released decision toward more than one set.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional

from ..operation_context_v2 import session_context_v2_hash
from ..protocol_v2 import bundle_hash_v2, decode_proof_bundle_v2
from ..release_v2 import V2ReleasedDecision
from ..scope import validate_required_scope_v2
from ..signing_v2 import key_id_v2
from ..types import HybridPublicKey
from ..verify_v2_preflight import clone_hybrid_public_key, equal_hybrid_public_keys


class ApprovalError(Exception):
    """Base class of the ledger's refusal errors."""


class ApprovalNotReleasedError(ApprovalError):
    pass


class ApprovalActionMismatchError(ApprovalError):
    pass


class ApprovalRootMismatchError(ApprovalError):
    pass


class ApprovalSlotFilledError(ApprovalError):
    pass


class ApprovalReusedError(ApprovalError):
    pass


class ApprovalIncompleteError(ApprovalError):
    pass


class ApprovalExpiredError(ApprovalError):
    pass


class ApprovalAlreadyExecutedError(ApprovalError):
    pass


class ApprovalSetInvalidError(ApprovalError):
    pass


class ApprovalSetUnknownError(ApprovalError):
    pass


class ApprovalSetAlreadyExistsError(ApprovalError):
    pass


@dataclass
class ApprovalSetTestOnly:
    approval_set_id: str = ""
    verifier_id: str = ""
    workspace_id: str = ""
    session_id: str = ""
    agent_public_key: Optional[HybridPublicKey] = None
    required_scope: str = ""
    request_hash: bytes = b""
    roots: tuple = ()


@dataclass
class _ApprovalState:
    set: ApprovalSetTestOnly
    agent_id: str
    root_ids: tuple
    session_context: bytes
    approvals: list = field(default_factory=lambda: [None, None])
    executed: bool = False


class ApprovalLedgerTestOnly:
    """Each operation is one atomic step under a lock."""

    def __init__(self):
        self._lock = threading.Lock()
        self._sets: dict = {}
        self._recorded: dict = {}

    def open(self, s: ApprovalSetTestOnly) -> None:
        try:
            validate_required_scope_v2(s.required_scope)
            scope_ok = True
        except Exception:  # noqa: BLE001
            scope_ok = False
        if not s.approval_set_id or len(s.request_hash or b"") != 32 or not scope_ok or len(s.roots) != 2:
            raise ApprovalSetInvalidError()
        try:
            agent_id = key_id_v2(s.agent_public_key)
            root_ids = (key_id_v2(s.roots[0]), key_id_v2(s.roots[1]))
        except Exception as exc:  # noqa: BLE001
            raise ApprovalSetInvalidError() from exc
        if root_ids[0] == root_ids[1]:
            raise ApprovalSetInvalidError()
        try:
            session_context = session_context_v2_hash(
                verifier_id=s.verifier_id, workspace_id=s.workspace_id, agent_id=agent_id, session_id=s.session_id,
                invocation_id=s.approval_set_id, request_hash=bytes(s.request_hash))
        except Exception as exc:  # noqa: BLE001
            raise ApprovalSetInvalidError() from exc
        with self._lock:
            if s.approval_set_id in self._sets:
                raise ApprovalSetAlreadyExistsError()
            stored = ApprovalSetTestOnly(
                approval_set_id=s.approval_set_id, verifier_id=s.verifier_id, workspace_id=s.workspace_id,
                session_id=s.session_id, agent_public_key=clone_hybrid_public_key(s.agent_public_key),
                required_scope=s.required_scope, request_hash=bytes(s.request_hash),
                roots=(clone_hybrid_public_key(s.roots[0]), clone_hybrid_public_key(s.roots[1])))
            self._sets[s.approval_set_id] = _ApprovalState(set=stored, agent_id=agent_id, root_ids=root_ids,
                                                           session_context=bytes(session_context))

    def record_approval(self, set_id: str, slot: int, decision: Optional[V2ReleasedDecision], bundle_wire: bytes) -> bool:
        if slot not in (0, 1):
            raise ValueError("v2reference: slot must be 0 or 1")
        if not isinstance(decision, V2ReleasedDecision) or decision.decision() != "allow":
            raise ApprovalNotReleasedError()
        try:
            receipt = decision.receipt()
        except Exception as exc:  # noqa: BLE001
            raise ApprovalNotReleasedError() from exc
        try:
            bundle = decode_proof_bundle_v2(bytes(bundle_wire))
            bundle_hash = bundle_hash_v2(bundle)
        except Exception as exc:  # noqa: BLE001
            raise ApprovalActionMismatchError() from exc
        if bundle_hash != receipt.bundle_hash:
            raise ApprovalActionMismatchError()
        claim_id = decision.claim_id()
        with self._lock:
            state = self._sets.get(set_id)
            if state is None:
                raise ApprovalSetUnknownError()
            owner = self._recorded.get(claim_id)
            if owner is not None and owner != set_id:
                raise ApprovalReusedError()
            s = state.set
            if (receipt.verifier_id != s.verifier_id or bundle.verifier_id != s.verifier_id
                    or receipt.agent_id != state.agent_id or bundle.agent_id != state.agent_id
                    or not equal_hybrid_public_keys(bundle.agent_pub_key, s.agent_public_key)
                    or receipt.required_scope != s.required_scope
                    or bundle.session_context is None or bytes(bundle.session_context) != state.session_context):
                raise ApprovalActionMismatchError()
            if not bundle.delegations:
                raise ApprovalRootMismatchError()
            root = bundle.delegations[-1]
            if (root.issuer_id != state.root_ids[slot] or not equal_hybrid_public_keys(root.issuer_pub_key, s.roots[slot])
                    or state.root_ids[slot] not in (receipt.issuer_ids or [])):
                raise ApprovalRootMismatchError()
            current = state.approvals[slot]
            if current is not None:
                if current[0] != claim_id:
                    raise ApprovalSlotFilledError()
            else:
                state.approvals[slot] = (claim_id, decision)
                self._recorded[claim_id] = set_id
            return state.approvals[0] is not None and state.approvals[1] is not None

    def execute(self, ctx, set_id: str, clock) -> None:
        with self._lock:
            state = self._sets.get(set_id)
            if state is None:
                raise ApprovalSetUnknownError()
            if state.executed:
                raise ApprovalAlreadyExecutedError()
            if state.approvals[0] is None or state.approvals[1] is None:
                raise ApprovalIncompleteError()
            for _, decision in state.approvals:
                if not decision.allowed(ctx, clock):
                    raise ApprovalExpiredError()
            state.executed = True
