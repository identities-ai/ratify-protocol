# SPDX-License-Identifier: Apache-2.0
"""The principal side: identities, signed delegations, and signed status.

This is the only place authority is *created* or *withdrawn*. In a real
deployment this code runs wherever the principal's keys live, a person's
device, an HSM, a CI signing step, and never inside the agent.

Protocol v2. Every party holds a hybrid Ed25519 + ML-DSA-65 key and is named
by its 64-hex key ID. The principal signs delegations with its root key and
signs revocation status with a *separate* status key: the root key can never
sign status for itself (SPEC-v2 role separation), so a stolen status key
cannot mint authority and a stolen root key cannot quietly un-revoke.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass

from ratify_protocol_v2 import background, key_id_v2
from ratify_protocol_v2.constraints_v2 import CONSTRAINT_MAX_AMOUNT, ConstraintV2
from ratify_protocol_v2.protocol_v2 import (
    DelegationCertV2,
    encode_revocation_list_v2,
    encode_revocation_push_v2,
    sign_delegation_cert_v2,
)
from ratify_protocol_v2.security_journal_v2 import (
    configure_status_key_epoch_v2,
    record_security_key_role_v2,
)
from ratify_protocol_v2.signing_v2 import generate_keypair_v2
from ratify_protocol_v2.status_publisher_v2 import new_v2_status_publisher_with_key
from ratify_protocol_v2.types import HybridPrivateKey, HybridPublicKey
from ratify_protocol_v2.v2reference.journal import new_journal_store

#: Wire object type codes for signed status evidence (SPEC-v2 §4).
STATUS_OBJECT_REVOCATION_LIST = 3
STATUS_OBJECT_REVOCATION_PUSH = 5

#: How long one signed status publication stays fresh. The receiver's status
#: policy accepts nothing older, so a principal that stops publishing makes its
#: delegations fail closed as status_stale rather than silently stay valid.
STATUS_LIFETIME_SECONDS = 3600


@dataclass(frozen=True)
class Party:
    """A principal or agent, as the protocol names it: a public key and the
    64-hex key ID derived from it."""

    id: str
    public_key: HybridPublicKey


def _party() -> tuple[Party, HybridPrivateKey]:
    pub, priv = generate_keypair_v2()
    return Party(id=key_id_v2(pub), public_key=pub), priv


def new_principal() -> tuple[Party, HybridPrivateKey]:
    """A principal's hybrid root identity."""
    return _party()


def new_agent(name: str = "") -> tuple[Party, HybridPrivateKey]:
    """An agent's own hybrid keypair. The agent generates this itself; the
    private half never leaves the agent. ``name`` is a label for readers only;
    a v2 identity is its key."""
    del name
    return _party()


def max_amount_micros(limit_micros: int, currency: str = "USD") -> ConstraintV2:
    """A per-action ceiling in integer micro-units (10^-6 of the major unit).

    v2 has no floating point anywhere on the wire, so 100.00 USD is
    ``100_000_000``. There is no NaN to smuggle past a comparison."""
    return ConstraintV2(
        type=CONSTRAINT_MAX_AMOUNT, currency=currency, max_amount_micros=limit_micros
    )


def resource_bound(resource_id: str) -> ConstraintV2:
    """Authority that names the one resource it covers, compared byte for byte."""
    return ConstraintV2(type="resource_path", resource_id=resource_id)


def sign_cert(
    *,
    issuer_id: str,
    issuer_pub: HybridPublicKey,
    issuer_priv: HybridPrivateKey,
    subject_id: str,
    subject_pub: HybridPublicKey,
    scope: list[str],
    constraints: list[ConstraintV2],
    issued_at: int,
    expires_at: int,
) -> DelegationCertV2:
    """Sign one delegation from an issuer to a subject.

    Used for both the principal's root delegation and for subdelegation, the
    protocol treats them identically, which is why non-amplification has to be
    enforced at verification rather than at issuance.
    """
    return sign_delegation_cert_v2(
        DelegationCertV2(
            version=2,
            cert_id=uuid.uuid4().hex,
            issuer_id=issuer_id,
            issuer_pub_key=issuer_pub,
            subject_id=subject_id,
            subject_pub_key=subject_pub,
            scope=list(scope),
            constraints=list(constraints),
            issued_at=issued_at,
            expires_at=expires_at,
        ),
        issuer_priv,
    )


class StatusAuthority:
    """The principal's signed revocation status, under a separate status key.

    Replaces v1's injected ``is_revoked`` callback. A receiver no longer asks a
    function it was handed whether a certificate is revoked; it verifies a
    status object signed by a key it configured for this principal, applies it
    to its own journal, and only then derives a status. Whatever carries the
    objects to the receiver (here, :class:`StatusFeed`) is untrusted transport.
    """

    def __init__(self, principal: Party, now: int) -> None:
        self._ctx = background()
        self.issuer = principal
        self.status_pub, status_priv = generate_keypair_v2()
        self.status_key_id = key_id_v2(self.status_pub)
        # The principal's own record of key roles. Refuses a status key that is
        # also the root key, before anything is signed.
        roles = new_journal_store()
        record_security_key_role_v2(self._ctx, roles, "issuer", principal.public_key)
        configure_status_key_epoch_v2(self._ctx, roles, principal.id, 1, self.status_pub)
        self._publisher = new_v2_status_publisher_with_key(
            self._ctx, roles, principal.public_key, status_priv, STATUS_LIFETIME_SECONDS
        )
        self._lock = threading.Lock()
        genesis = self._publisher.genesis(self._ctx, now)
        self._state = genesis.state
        self.objects: list[tuple[int, bytes]] = [
            (STATUS_OBJECT_REVOCATION_LIST, encode_revocation_list_v2(genesis.list))
        ]

    def revoke(self, cert_id: str, at: int) -> None:
        """Revoke one certificate: a signed push plus the cumulative list."""
        with self._lock:
            # A status update must be strictly later than the last one.
            at = max(at, self._state.updated_at + 1)
            out = self._publisher.revoke(self._ctx, self._state, [cert_id], at)
            self._state = out.state
            self.objects = [
                (STATUS_OBJECT_REVOCATION_PUSH, encode_revocation_push_v2(out.push)),
                (STATUS_OBJECT_REVOCATION_LIST, encode_revocation_list_v2(out.list)),
            ]

    def heartbeat(self, at: int) -> None:
        """Re-sign the current list so it stays inside the freshness window."""
        with self._lock:
            at = max(at, self._state.updated_at + 1)
            out = self._publisher.heartbeat(self._ctx, self._state, at)
            self._state = out.state
            self.objects = [(STATUS_OBJECT_REVOCATION_LIST, encode_revocation_list_v2(out.list))]

    def published(self) -> list[tuple[int, bytes]]:
        with self._lock:
            return list(self.objects)
