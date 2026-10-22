"""Minimal signed-status publisher (Go status_publisher_v2.go, SPEC-v2 §5.4).

A v2 allow needs current signed status for every certificate in the chain.
:class:`V2StatusPublisher` produces that feed for one issuer under a
separate status key: a genesis full list, same-sequence heartbeats that
refresh freshness, and revocations as a push plus the cumulative full list
at the next sequence. Each operation is a pure transition of
:class:`V2StatusPublisherState`; the caller MUST durably persist the returned
state before publishing the returned objects, so a crash can never sign two
different bodies at one sequence.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field, replace
from typing import Optional

from . import security_journal_v2 as sj
from . import status_state_v2 as ss
from .context_v2 import Context, require_context
from .errors_v2 import V2Error, V2ErrorClass, classify
from .types import HybridPublicKey
from .types_v2 import MAX_SAFE_INTEGER, is_int

MAX_REVOCATION_PUSH_REFS_V2 = 512
MAX_REVOCATION_LIST_REFS_V2 = 10000
MAX_IDENTIFIER_LENGTH_BYTES = 512


@dataclass
class V2StatusPublisherState:
    """The publisher's durable state. ``sequence`` is the last signed
    sequence, ``updated_at`` the updated_at of the last signed full list, and
    ``revoked`` the cumulative sorted set."""

    issuer_id: str = ""
    status_key_id: str = ""
    sequence: int = 0
    updated_at: int = 0
    revoked: list = field(default_factory=list)


@dataclass
class V2StatusPublication:
    """One transition's output: the next state and the signed objects to
    publish after that state is durable. ``push`` is ``None`` except for a
    revocation."""

    state: V2StatusPublisherState
    list: object = None  # RevocationListV2
    push: object = None  # RevocationPushV2


def _clone_key(pub: HybridPublicKey) -> HybridPublicKey:
    return HybridPublicKey(ed25519=bytes(pub.ed25519), ml_dsa_65=bytes(pub.ml_dsa_65))


def _config_error(message: str) -> V2Error:
    return V2Error(V2ErrorClass.CONFIGURATION_INVALID, message)


def _revoked_refs(ids: list) -> list:
    """Build the wire module's revoked array for these certificate IDs."""
    w = ss._wire()
    ref_type = getattr(w, "RevokedCertV2", None)
    return [ref_type(cert_id=i) if ref_type is not None else i for i in ids]


def _utf8(value: str) -> Optional[bytes]:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        return None


class V2StatusPublisher:
    """Signs status for one issuer under one status key. Construct it with
    :func:`new_v2_status_publisher`."""

    __slots__ = ("_issuer_id", "_status_key", "_status_key_id", "_signer", "_lifetime")

    def __init__(self, *, _token: object, issuer_id: str, status_key: HybridPublicKey, status_key_id: str, signer, lifetime: int):
        if _token is not _CONSTRUCT:
            raise TypeError("use new_v2_status_publisher to construct a V2StatusPublisher")
        self._issuer_id = issuer_id
        self._status_key = _clone_key(status_key)
        self._status_key_id = status_key_id
        self._signer = signer
        self._lifetime = lifetime

    def issuer_id(self) -> str:
        """The issuer binding a verifier configures."""
        return self._issuer_id

    def status_key(self) -> HybridPublicKey:
        """A copy of the complete status public key."""
        return _clone_key(self._status_key)

    def genesis(self, ctx: Context, updated_at: int) -> V2StatusPublication:
        """Sign the first full list: sequence 1, an empty revoked set."""
        require_context(ctx)
        state = V2StatusPublisherState(issuer_id=self._issuer_id, status_key_id=self._status_key_id, revoked=[])
        return self._list(ctx, state, 1, updated_at)

    def heartbeat(self, ctx: Context, state: V2StatusPublisherState, updated_at: int) -> V2StatusPublication:
        """Re-sign the current sequence and revoked set with a later
        updated_at, which refreshes freshness without a new sequence."""
        require_context(ctx)
        self._check_state(state, updated_at)
        return self._list(ctx, state, state.sequence, updated_at)

    def revoke(self, ctx: Context, state: V2StatusPublisherState, cert_ids, at: int) -> V2StatusPublication:
        """Advance one sequence: a push carrying exactly the newly revoked
        certificate IDs and the cumulative full list at the same sequence,
        both timestamped ``at``. Every ID must be new, unique, and 1..512
        bytes of UTF-8."""
        require_context(ctx)
        self._check_state(state, at)
        if not isinstance(cert_ids, (list, tuple)) or len(cert_ids) == 0 or len(cert_ids) > MAX_REVOCATION_PUSH_REFS_V2:
            raise ValueError(f"v2 status revocation must name 1..{MAX_REVOCATION_PUSH_REFS_V2} certificate IDs")
        if not all(isinstance(i, str) for i in cert_ids):
            raise ValueError("v2 status revocation IDs must be strings")
        added = sorted(cert_ids, key=lambda s: s.encode("utf-8", "surrogatepass"))
        for i, cert_id in enumerate(added):
            raw = _utf8(cert_id)
            if raw is None or cert_id == "" or len(raw) > MAX_IDENTIFIER_LENGTH_BYTES or (i > 0 and added[i - 1] == cert_id):
                raise ValueError(f"v2 status revocation IDs must be unique UTF-8 of 1..{MAX_IDENTIFIER_LENGTH_BYTES} bytes")
            index = bisect.bisect_left(state.revoked, cert_id)
            if index < len(state.revoked) and state.revoked[index] == cert_id:
                raise ValueError(f"v2 certificate {cert_id!r} is already revoked; revocation is monotonic")
        if len(state.revoked) + len(added) > MAX_REVOCATION_LIST_REFS_V2:
            raise ValueError(f"v2 status list would exceed {MAX_REVOCATION_LIST_REFS_V2} revoked references")
        sequence = state.sequence + 1
        if sequence > MAX_SAFE_INTEGER:
            raise ValueError("v2 status sequence is exhausted")
        w = ss._wire()
        from .protocol_v2 import placeholder_signature_v2

        push = w.sign_revocation_push_v2_with_signer(
            ctx,
            w.RevocationPushV2(version=2, issuer_id=self._issuer_id, sequence=sequence, pushed_at=at,
                               revoked=_revoked_refs(added), signature=placeholder_signature_v2()),
            self._issuer_id, self._status_key, self._signer,
        )
        nxt = replace(state, revoked=sorted(list(state.revoked) + added))
        out = self._list(ctx, nxt, sequence, at)
        out.push = push
        return out

    def _check_state(self, state: V2StatusPublisherState, at: int) -> None:
        revoked = getattr(state, "revoked", None)
        if (
            not isinstance(state, V2StatusPublisherState) or state.issuer_id != self._issuer_id
            or state.status_key_id != self._status_key_id or not is_int(state.sequence)
            or state.sequence < 1 or state.sequence > MAX_SAFE_INTEGER
            or not ss._valid_timestamp(state.updated_at) or not isinstance(revoked, list)
            or not all(isinstance(i, str) for i in revoked)
            or revoked != sorted(revoked) or len(set(revoked)) != len(revoked)
        ):
            raise _config_error(
                "v2 status publisher state does not belong to this issuer and status key, or its revoked set is not sorted and unique")
        if not is_int(at) or at <= state.updated_at:
            raise ValueError(f"v2 status update time {at} must be later than the last list's updated_at {state.updated_at}")

    def _list(self, ctx: Context, state: V2StatusPublisherState, sequence: int, updated_at: int) -> V2StatusPublication:
        if not ss._valid_timestamp(updated_at) or not ss._valid_timestamp(updated_at + self._lifetime):
            raise ValueError("v2 status list times leave the timestamp domain")
        w = ss._wire()
        from .protocol_v2 import placeholder_signature_v2

        lst = w.sign_revocation_list_v2_with_signer(
            ctx,
            w.RevocationListV2(version=2, issuer_id=self._issuer_id, updated_at=updated_at,
                               next_update=updated_at + self._lifetime, sequence=sequence,
                               revoked=_revoked_refs(list(state.revoked)), signature=placeholder_signature_v2()),
            self._issuer_id, self._status_key, self._signer,
        )
        nxt = replace(state, sequence=sequence, updated_at=updated_at, revoked=list(state.revoked))
        return V2StatusPublication(state=nxt, list=lst)


_CONSTRUCT = object()


def new_v2_status_publisher(ctx: Context, roles, issuer_key: HybridPublicKey, status_signer, lifetime_seconds: int) -> V2StatusPublisher:
    """Bind an issuer's complete key to a separate status signer using the
    deployment's authenticated role configuration: the anchored
    SecurityJournalV2 in ``roles``, whose key-role history records every
    non-status key the deployment knows and whose status-key history binds
    the issuer to its current status key.

    Refuses with configuration_invalid, before any signature exists, when
    ``roles`` is missing or does not load as an anchored journal; when the
    issuer key is not recorded under a non-status role; when the status key's
    ID or either component equals the ID or a component of any recorded
    non-status key; or when the status key is not the issuer's highest-epoch
    configured status key. ``lifetime_seconds`` (1..86400) sets
    next_update - updated_at for every full list."""
    require_context(ctx)
    if not is_int(lifetime_seconds) or lifetime_seconds < 1 or lifetime_seconds > ss.V2_MAX_STATUS_LIFETIME_SECONDS:
        raise _config_error(f"v2 status list lifetime must be 1..{ss.V2_MAX_STATUS_LIFETIME_SECONDS} seconds")
    if roles is None:
        raise _config_error("v2 status publisher requires the authenticated role configuration")
    try:
        issuer_binding = sj.key_role_binding_v2("issuer", issuer_key)
    except Exception as exc:
        raise classify(V2ErrorClass.CONFIGURATION_INVALID, ValueError(f"v2 status publisher issuer key: {exc}")) from exc
    if status_signer is None:
        raise _config_error("v2 status publisher requires a status signer")
    from .signing_v2 import signer_public_key_v2

    try:
        status_key = signer_public_key_v2(status_signer)
        status_binding = sj.key_role_binding_v2("status", status_key)
    except V2Error:
        raise
    except Exception as exc:
        raise classify(V2ErrorClass.CONFIGURATION_INVALID, exc) from exc
    try:
        journal = sj.load_anchored_security_journal_v2(ctx, roles)
    except Exception as exc:
        raise classify(V2ErrorClass.CONFIGURATION_INVALID,
                       ValueError(f"v2 status publisher role configuration: {exc}")) from exc
    issuer_known = False
    for b in journal.key_role_history:
        if b.role == "status":
            continue
        if b.key_id == issuer_binding.key_id and b.ed25519_digest == issuer_binding.ed25519_digest and b.ml_dsa_65_digest == issuer_binding.ml_dsa_65_digest:
            issuer_known = True
        if (
            b.key_id == status_binding.key_id or b.ed25519_digest == status_binding.ed25519_digest
            or b.ml_dsa_65_digest == status_binding.ml_dsa_65_digest
            or b.ed25519_digest == status_binding.ml_dsa_65_digest or b.ml_dsa_65_digest == status_binding.ed25519_digest
        ):
            raise _config_error(
                f"v2 status key reuses the key or a component of recorded {b.role} key {b.key_id}; status keys must be role-separated")
    if not issuer_known:
        raise _config_error("v2 status publisher issuer key is not recorded under a non-status role")
    current = None
    for b in journal.status_key_history:
        if b.issuer_id == issuer_binding.key_id and (current is None or b.epoch > current.epoch):
            current = b
    if (
        current is None or current.epoch == 0 or current.status_key_id != status_binding.key_id
        or current.ed25519_digest != status_binding.ed25519_digest or current.ml_dsa_65_digest != status_binding.ml_dsa_65_digest
    ):
        raise _config_error("v2 status signer is not the issuer's current configured status key")
    return V2StatusPublisher(
        _token=_CONSTRUCT, issuer_id=issuer_binding.key_id, status_key=status_key,
        status_key_id=status_binding.key_id, signer=status_signer, lifetime=lifetime_seconds,
    )
