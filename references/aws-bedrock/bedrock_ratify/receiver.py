r"""Agent 2's protected side: verify first, then read the directory.

This is the only module that touches C:\SideEvents. Every path into the real
filesystem runs behind `verify_bundle`, so a request without a valid, in-scope,
unrevoked, fresh, resource-bound proof cannot reach `os.scandir` at all.

The receiver is deliberately not the issuer: it holds no principal key and
cannot mint authority for itself. It holds a trust policy (which root it
recognises) and the verifier key it signs receipts with.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Optional

from ratify_protocol import (
    MemoryChallengeStore,
    ProofBundle,
    SessionContextInputs,
    VerificationReceipt,
    VerifierContext,
    VerifyOptions,
    base64_standard_encode,
    build_session_context,
    encode_verification_receipt,
    issue_verification_receipt,
    receipt_hash,
    verify_bundle,
)

from .config import (
    CHALLENGE_TTL_SECONDS,
    PROTECTED_ROOT,
    REQUIRED_SCOPE,
    RESOURCE_ID,
    VERIFIER_ID,
    WORKSPACE_ID,
)
from .identity import Party


@dataclass
class DirectoryRequest:
    """What agent 1 is asking for.

    The resource and path are hashed into the session context, so a proof
    minted for one request cannot be lifted onto another.
    """

    session_id: str
    invocation_id: str
    resource_id: str
    path: str  # logical path inside the resource, e.g. "/" or "/tools"

    def request_hash_input(self) -> bytes:
        """A 32-byte digest over exactly what is being asked for."""
        return hashlib.sha256(
            f"{self.resource_id}|{self.path}".encode("utf-8")
        ).digest()


@dataclass
class Decision:
    allowed: bool
    reason: str
    entries: list[dict] = field(default_factory=list)
    receipt_b64: str = ""
    receipt_hash_b64: str = ""
    human_id: str = ""
    agent_id: str = ""
    granted_scope: list[str] = field(default_factory=list)
    handler_invocations: int = 0


class SideEventsCustodian:
    """The receiving agent's authority gate and protected handler."""

    def __init__(self, verifier: Party, trusted_root_id: str, root: str = PROTECTED_ROOT):
        self.verifier = verifier
        self.trusted_root_id = trusted_root_id
        self.root = Path(root)
        self.challenges = MemoryChallengeStore()
        self._revoked: set[str] = set()
        self._prev_receipt_hash: Optional[bytes] = None
        self.handler_invocations = 0

    # -- trust and revocation state -----------------------------------------

    def revoke(self, cert_id: str) -> None:
        """The kill switch.

        Applied locally here; in a deployment this arrives as a signed
        RevocationPush from the principal and the receiver never gets a vote.
        """
        self._revoked.add(cert_id)

    def is_revoked(self, cert_id: str):
        """RevocationProvider: returns (is_revoked, error_or_None)."""
        return (cert_id in self._revoked, None)

    # -- binding -------------------------------------------------------------

    def session_context(self, req: DirectoryRequest, agent_id: str) -> bytes:
        return build_session_context(
            SessionContextInputs(
                verifier_id=VERIFIER_ID,
                workspace_id=WORKSPACE_ID,
                agent_id=agent_id,
                session_id=req.session_id,
                invocation_id=req.invocation_id,
                request_hash=req.request_hash_input(),
            )
        )

    def issue_challenge(self, req: DirectoryRequest, agent_id: str) -> tuple[bytes, bytes]:
        """Hand the caller a single-use nonce bound to this exact request."""
        ctx = self.session_context(req, agent_id)
        challenge, _expires_at = self.challenges.issue(ctx, CHALLENGE_TTL_SECONDS)
        return challenge, ctx

    # -- the gate ------------------------------------------------------------

    def list_directory(self, req: DirectoryRequest, bundle: ProofBundle) -> Decision:
        ctx = self.session_context(req, bundle.agent_id)

        result = verify_bundle(
            bundle,
            VerifyOptions(
                required_scope=REQUIRED_SCOPE,
                session_context=ctx,
                challenge_store=self.challenges,
                force_revocation_check=True,
                revocation=self,
                context=VerifierContext(
                    has_resource=True,
                    requested_resource_id=req.resource_id,
                    requested_path=req.path,
                ),
            ),
        )

        receipt = issue_verification_receipt(
            bundle,
            result,
            VERIFIER_ID,
            self.verifier.public_key,
            self.verifier.private_key,
            self._prev_receipt_hash,
            int(time.time()),
        )
        self._prev_receipt_hash = receipt_hash(receipt)
        receipt_fields = dict(
            receipt_b64=encode_verification_receipt(receipt),
            receipt_hash_b64=base64_standard_encode(self._prev_receipt_hash),
        )

        if not result.valid:
            reason = result.error_reason or "verification failed"
            status = str(result.identity_status)
            return Decision(
                False,
                reason if reason.startswith(status) else f"{status}: {reason}",
                handler_invocations=self.handler_invocations,
                **receipt_fields,
            )
        if result.human_id != self.trusted_root_id:
            return Decision(
                False,
                "untrusted_root: the delegation verifies but is not anchored to a "
                "principal this custodian recognises",
                handler_invocations=self.handler_invocations,
                **receipt_fields,
            )
        if req.resource_id != RESOURCE_ID:
            return Decision(
                False,
                f"unserved_resource: this custodian serves {RESOURCE_ID} only",
                handler_invocations=self.handler_invocations,
                **receipt_fields,
            )

        # ---- allow branch: the only path to the filesystem ------------------
        try:
            entries = self._read(req.path)
        except (ValueError, OSError) as exc:
            return Decision(
                False,
                f"resource_error: {exc}",
                handler_invocations=self.handler_invocations,
                **receipt_fields,
            )

        self.handler_invocations += 1
        return Decision(
            True,
            "authorized",
            entries=entries,
            human_id=result.human_id,
            agent_id=result.agent_id,
            granted_scope=list(result.granted_scope),
            handler_invocations=self.handler_invocations,
            **receipt_fields,
        )

    # -- the handler ---------------------------------------------------------

    def _read(self, logical_path: str) -> list[dict]:
        """Map a verified logical path onto the real directory and list it.

        Verification has already refused anything outside the granted prefix;
        this still resolves and re-checks containment, because a proof layer
        cannot enforce a filesystem boundary from inside a signature.
        """
        rel = PurePosixPath(logical_path)
        if not rel.is_absolute():
            raise ValueError("logical path must be absolute")
        target = (self.root / Path(*rel.parts[1:])).resolve()
        root = self.root.resolve()
        if target != root and root not in target.parents:
            raise ValueError("resolved path escapes the protected root")
        if not target.is_dir():
            raise ValueError("not a directory")
        out: list[dict] = []
        with os.scandir(target) as it:
            for entry in sorted(it, key=lambda e: e.name):
                out.append(
                    {
                        "name": entry.name,
                        "type": "dir" if entry.is_dir() else "file",
                        "bytes": entry.stat().st_size if entry.is_file() else None,
                    }
                )
        return out
