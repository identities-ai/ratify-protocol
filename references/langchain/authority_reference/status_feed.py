"""Signed revocation status for the reference (Protocol v2, SPEC-v2 §5.4).

DEVELOPMENT ONLY. Every issuer in a delegation chain signs its revocation list
with its own status key, separate from the key that issues delegations. The
SDK status publisher enforces that separation from an anchored role journal
and refuses to sign under an issuer or root key. Here the publisher state and
the role journal are the SDK's in-memory reference stores; a production
issuer persists the next publisher state before it publishes the signed
objects (SPEC-v2 §5.4, publisher durability).

The feed is untrusted transport. A receiver authenticates every object
against the status keys in its own trust configuration and ingests it into
its own security journal before it derives a status. A v2 ``allow`` needs
current signed status for every certificate in the chain, so a verifier that
never calls Ratify infrastructure still needs a local status feed like this
one.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import threading
from typing import Callable

from ratify_protocol.v2 import background, key_id_v2
from ratify_protocol.v2.protocol_v2 import encode_revocation_list_v2
from ratify_protocol.v2.security_journal_v2 import (
    configure_status_key_epoch_v2,
    record_security_key_role_v2,
)
from ratify_protocol.v2.signing_v2 import REVOCATION_LIST, generate_keypair_v2
from ratify_protocol.v2.status_batch_v2 import (
    V2StatusEvidenceBatch,
    V2StatusEvidenceObject,
    decode_v2_status_evidence_batch,
    encode_v2_status_evidence_batch,
)
from ratify_protocol.v2.status_publisher_v2 import (
    V2StatusPublication,
    V2StatusPublisher,
    new_v2_status_publisher_with_key,
)
from ratify_protocol.v2.types import HybridPublicKey
from ratify_protocol.v2.v2reference.journal import new_journal_store


StatusSource = Callable[[str], V2StatusEvidenceBatch]


@dataclass
class _IssuerFeed:
    publisher: V2StatusPublisher
    publication: V2StatusPublication


class StatusAuthority:
    """The issuers' side: one status publisher per issuer key."""

    def __init__(self, *, lifetime_seconds: int = 3600) -> None:
        self._ctx = background()
        # The publishers' own role configuration. A verifier never shares it;
        # it keeps its own journal (see receiver.py).
        self._roles = new_journal_store()
        self._lifetime = lifetime_seconds
        self._feeds: dict[str, _IssuerFeed] = {}
        self._lock = threading.Lock()

    def add_issuer(self, issuer_key: HybridPublicKey, *, at: int) -> HybridPublicKey:
        """Give an issuer a fresh status key and sign its genesis list."""
        issuer_id = key_id_v2(issuer_key)
        status_public, status_private = generate_keypair_v2()
        with self._lock:
            if issuer_id in self._feeds:
                raise ValueError("issuer already has a status feed")
            record_security_key_role_v2(self._ctx, self._roles, "issuer", issuer_key)
            configure_status_key_epoch_v2(self._ctx, self._roles, issuer_id, 1, status_public)
            publisher = new_v2_status_publisher_with_key(
                self._ctx, self._roles, issuer_key, status_private, self._lifetime
            )
            self._feeds[issuer_id] = _IssuerFeed(publisher, publisher.genesis(self._ctx, at))
        return status_public

    def status_keys(self) -> dict[str, HybridPublicKey]:
        """Public status keys by issuer ID, for a receiver's trust configuration."""
        with self._lock:
            return {issuer: feed.publisher.status_key() for issuer, feed in self._feeds.items()}

    def revoke(self, issuer_id: str, cert_id: str, *, at: int) -> None:
        """Revoke one certificate: the issuer signs the next sequence."""
        with self._lock:
            feed = self._feeds[issuer_id]
            feed.publication = feed.publisher.revoke(self._ctx, feed.publication.state, [cert_id], at)

    def heartbeat(self, *, at: int) -> None:
        """Re-sign every current list with a later update time."""
        with self._lock:
            for feed in self._feeds.values():
                feed.publication = feed.publisher.heartbeat(self._ctx, feed.publication.state, at)

    def evidence(self, issuer_id: str) -> V2StatusEvidenceBatch:
        """The latest signed full list for one issuer (cumulative)."""
        with self._lock:
            feed = self._feeds.get(issuer_id)
            if feed is None:
                return V2StatusEvidenceBatch(objects=[])
            wire = encode_revocation_list_v2(feed.publication.list)
        return V2StatusEvidenceBatch(objects=[V2StatusEvidenceObject(object_type=REVOCATION_LIST, wire=wire)])

    def write(self, directory: Path) -> None:
        """Publish every issuer's latest list as a status evidence batch file."""
        directory.mkdir(parents=True, exist_ok=True)
        for issuer_id in self.status_keys():
            batch = encode_v2_status_evidence_batch(self.evidence(issuer_id))
            target = directory / f"{issuer_id}.json"
            staging = directory / f".{issuer_id}.json.tmp"
            staging.write_bytes(batch)
            staging.replace(target)


class DirectoryStatusSource:
    """The receiver's side of a file-based local feed.

    It reads a batch by the issuer ID that the verifier asks for, which comes
    from the receiver's trust configuration, never from the proof. A missing
    or unreadable file is an empty batch: status is then unavailable and the
    decision cannot be allow.
    """

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory)

    def __call__(self, issuer_id: str) -> V2StatusEvidenceBatch:
        if len(issuer_id) != 64 or not all(c in "0123456789abcdef" for c in issuer_id):
            return V2StatusEvidenceBatch(objects=[])
        try:
            return decode_v2_status_evidence_batch((self._directory / f"{issuer_id}.json").read_bytes())
        except Exception:  # noqa: BLE001 - unreadable evidence is no evidence
            return V2StatusEvidenceBatch(objects=[])
