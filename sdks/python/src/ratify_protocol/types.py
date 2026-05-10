"""Ratify Protocol v1 — Python type definitions.

Mirrors the Go reference types at module root of
github.com/identities-ai/ratify-protocol. v1 uses hybrid cryptography:
every signed object carries a HybridSignature composed of one Ed25519 and
one ML-DSA-65 (FIPS 204) component. Both must verify for the signature to
be accepted.

Field names use snake_case to match the canonical JSON wire format directly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Literal, Optional


PROTOCOL_VERSION: int = 1
MAX_DELEGATION_CHAIN_DEPTH: int = 3
CHALLENGE_WINDOW_SECONDS: int = 300

ED25519_PUBLIC_KEY_SIZE: int = 32
ED25519_SIGNATURE_SIZE: int = 64
MLDSA65_PUBLIC_KEY_SIZE: int = 1952
MLDSA65_SIGNATURE_SIZE: int = 3309


@dataclass
class HybridPublicKey:
    """Ed25519 + ML-DSA-65 public key pair.

    Canonical JSON form (keys in lex order):
        {"ed25519":"<base64-32-bytes>","ml_dsa_65":"<base64-1952-bytes>"}
    """
    ed25519: bytes  # 32 bytes
    ml_dsa_65: bytes  # 1952 bytes


@dataclass
class HybridSignature:
    """Ed25519 + ML-DSA-65 signature pair over the same canonical bytes.

    Both components MUST verify for the signature to be accepted.
    """
    ed25519: bytes  # 64 bytes
    ml_dsa_65: bytes  # 3309 bytes


@dataclass
class HybridPrivateKey:
    """Both component private keys. Never serialized to the wire.

    - ed25519: 32-byte seed (cryptography's private_bytes_raw format)
    - ml_dsa_65: full ML-DSA-65 secret key (4032 bytes, pqcrypto format)
    """
    ed25519: bytes
    ml_dsa_65: bytes


@dataclass
class Anchor:
    """Optional external binding for higher-assurance identity."""
    type: str  # "email" | "enterprise_sso" | "government_id"
    provider: str
    reference: str
    verified_at: int


@dataclass
class HumanRoot:
    """Master identity for a human (or tenant admin)."""
    id: str  # hex(SHA-256(ed25519_pub || ml_dsa_65_pub)[:16])
    public_key: HybridPublicKey
    created_at: int
    anchors: Optional[list[Anchor]] = None


@dataclass
class AgentIdentity:
    """An AI agent's identity — hybrid keypair + metadata."""
    id: str
    public_key: HybridPublicKey
    name: str
    agent_type: str  # "zoom_bot", "voice_agent", "mcp_server", "custom"
    created_at: int


@dataclass
class Constraint:
    """First-class bound on when/where/how much an agent may exercise its
    scopes. `type` discriminates the kind; remaining fields are kind-specific.

    Wire format is a tagged JSON object. Unknown `type` values MUST be
    rejected by conformant verifiers (fail-closed semantics).

    Zero-valued fields are omitted from canonical JSON to match Go's
    `omitempty` behavior — see to_canonical_dict().
    """
    type: str  # "geo_circle" | "geo_polygon" | "geo_bbox" | "time_window"
               # | "max_speed_mps" | "max_amount" | "max_rate"

    # Geo.
    lat: float = 0.0
    lon: float = 0.0
    radius_m: float = 0.0
    points: list[list[float]] = field(default_factory=list)  # geo_polygon
    min_lat: float = 0.0
    min_lon: float = 0.0
    max_lat: float = 0.0
    max_lon: float = 0.0
    min_alt_m: float = 0.0
    max_alt_m: float = 0.0

    # Time window.
    start: str = ""  # "HH:MM"
    end: str = ""
    tz: str = ""  # IANA zone

    # Magnitude.
    max_mps: float = 0.0
    max_amount: float = 0.0
    currency: str = ""  # ISO 4217

    # Rate.
    count: int = 0
    window_s: int = 0

    def to_canonical_dict(self) -> dict:
        """Return the canonical per-kind dict for this Constraint.

        Emits the `type` tag plus every field the Type requires — with zero
        values preserved. Fields irrelevant to this kind are omitted. This
        closes the v1 "zero-as-absence" ambiguity: a
        geo_circle at lat=0, lon=0 (equator / prime meridian) now
        serializes as {"type":"geo_circle","lat":0,"lon":0,"radius_m":R}
        instead of {"type":"geo_circle","radius_m":R}.

        Mirrors Go's Constraint.MarshalJSON and TS canonicalConstraintDict.
        """
        out: dict = {"type": self.type}
        if self.type == "geo_circle":
            out["lat"] = self.lat
            out["lon"] = self.lon
            out["radius_m"] = self.radius_m
        elif self.type == "geo_polygon":
            out["points"] = self.points
        elif self.type == "geo_bbox":
            out["max_lat"] = self.max_lat
            out["max_lon"] = self.max_lon
            out["min_lat"] = self.min_lat
            out["min_lon"] = self.min_lon
            if self.min_alt_m != 0.0 or self.max_alt_m != 0.0:
                out["max_alt_m"] = self.max_alt_m
                out["min_alt_m"] = self.min_alt_m
        elif self.type == "time_window":
            out["end"] = self.end
            out["start"] = self.start
            out["tz"] = self.tz
        elif self.type == "max_speed_mps":
            out["max_mps"] = self.max_mps
        elif self.type == "max_amount":
            out["currency"] = self.currency
            out["max_amount"] = self.max_amount
        elif self.type == "max_rate":
            out["count"] = self.count
            out["window_s"] = self.window_s
        # Unknown type: tag only. Verifier returns constraint_unknown.
        return out


@dataclass
class VerifierContext:
    """Application-supplied inputs for evaluating first-class constraints.

    A cert bearing a constraint whose required context field is absent will
    be rejected with `constraint_unverifiable` (fail-closed).
    """
    # Location — required by geo_circle, geo_polygon, geo_bbox.
    current_lat: Optional[float] = None
    current_lon: Optional[float] = None
    current_alt_m: Optional[float] = None

    # Velocity — required by max_speed_mps.
    current_speed_mps: Optional[float] = None

    # Transaction — required by max_amount.
    requested_amount: Optional[float] = None
    requested_currency: Optional[str] = None

    # Rate counter — required by max_rate. (cert_id, window_s) -> count
    invocations_in_window: Optional[Callable[[str, int], int]] = None


@dataclass
class DelegationCert:
    """Signed authorization from a principal to an agent.

    `scope` answers *what* the agent may do; `constraints` answer *where /
    when / how much* — first-class bounds evaluated at verify time against
    a caller-supplied VerifierContext.

    The signature is hybrid; both component signatures must verify
    independently against the IssuerPubKey for the cert to be accepted.
    """
    cert_id: str
    version: int  # = PROTOCOL_VERSION
    issuer_id: str
    issuer_pub_key: HybridPublicKey
    subject_id: str
    subject_pub_key: HybridPublicKey
    scope: list[str]
    # Always present in canonical JSON as `[]` when empty — never absent.
    constraints: list[Constraint] = field(default_factory=list)
    issued_at: int = 0
    expires_at: int = 0
    signature: HybridSignature = field(default_factory=lambda: HybridSignature(ed25519=b"", ml_dsa_65=b""))


@dataclass
class ProofBundle:
    """Proof an agent presents to a verifier.

    Used symmetrically in human-agent and agent-agent flows. v1.1 optional
    stream binding: when ``stream_id`` and ``stream_seq`` are both set, the
    bundle is "stream-bound" — it belongs to an ordered sequence of
    interactions sharing a stream_id. Both are signed into the challenge
    bytes (SPEC §6.4.2).
    """
    agent_id: str
    agent_pub_key: HybridPublicKey
    delegations: list[DelegationCert]  # [leaf, ..., root]
    challenge: bytes  # 32 random bytes
    challenge_at: int
    challenge_sig: HybridSignature
    session_context: bytes = b""  # optional 32-byte verifier/session binding
    stream_id: bytes = b""        # optional 32-byte v1.1 stream identifier
    stream_seq: int = 0           # optional monotonic sequence (>=1 when stream_id set)


IdentityStatus = Literal[
    "verified_human",
    "authorized_agent",
    "expired",
    "revoked",
    "scope_denied",
    "constraint_denied",
    "constraint_unverifiable",
    "constraint_unknown",
    "delegation_not_authorized",
    "invalid",
    "unauthorized",
]


@dataclass
class VerifyResult:
    """Deterministic output of verify_bundle(). Always check `valid` first."""
    valid: bool
    identity_status: IdentityStatus
    human_id: str = ""
    agent_id: str = ""
    agent_name: str = ""
    agent_type: str = ""
    granted_scope: list[str] = field(default_factory=list)
    error_reason: str = ""


@dataclass
class RevocationList:
    """Signed list of revoked cert IDs, served by the issuer."""
    issuer_id: str
    updated_at: int
    revoked_certs: list[str]
    signature: HybridSignature


@dataclass
class RevocationPush:
    """v1.1 signed push notification of newly revoked cert IDs."""
    issuer_id: str
    seq_no: int
    entries: list[str]
    pushed_at: int
    signature: HybridSignature = field(default_factory=lambda: HybridSignature(ed25519=b"", ml_dsa_65=b""))


@dataclass
class WitnessEntry:
    """v1.1 element in a hash-chain append-only witness log."""
    prev_hash: bytes    # 32 bytes; zeros for genesis
    entry_data: bytes
    timestamp: int
    witness_id: str
    signature: HybridSignature = field(default_factory=lambda: HybridSignature(ed25519=b"", ml_dsa_65=b""))


KeyRotationReason = Literal[
    "routine",
    "compromise_suspected",
    "device_lost",
    "recovery",
    "other",
]


@dataclass
class KeyRotationStatement:
    """Signed continuity statement from an old root key to a new root key."""
    version: int
    old_id: str
    old_pub_key: HybridPublicKey
    new_id: str
    new_pub_key: HybridPublicKey
    rotated_at: int
    reason: KeyRotationReason
    signature_old: HybridSignature = field(default_factory=lambda: HybridSignature(ed25519=b"", ml_dsa_65=b""))
    signature_new: HybridSignature = field(default_factory=lambda: HybridSignature(ed25519=b"", ml_dsa_65=b""))


@dataclass
class SessionToken:
    """v1.1 verifier-issued credential that caches a verified chain.

    MAC = HMAC-SHA256(session_secret, session_token_sign_bytes(token)). The
    session_secret is private to the verifier and never leaves its trust
    boundary. Streamed turns present this token plus a fresh challenge
    signature; the verifier checks the MAC and challenge sig without
    re-verifying the chain.
    """
    version: int
    session_id: str
    agent_id: str
    agent_pub_key: HybridPublicKey
    human_id: str
    granted_scope: list[str]  # sorted lex
    issued_at: int
    valid_until: int
    chain_hash: bytes  # 32 bytes — SHA-256 over concatenated delegation sign bytes
    mac: bytes         # 32 bytes — HMAC-SHA256 over canonical signable bytes


@dataclass
class ReceiptParty:
    """A party in a TransactionReceipt with its proof of authority."""
    party_id: str
    role: str
    agent_id: str
    agent_pub_key: HybridPublicKey
    proof_bundle: ProofBundle


@dataclass
class ReceiptPartySignature:
    """One party's hybrid signature over the canonical receipt signable."""
    party_id: str
    signature: HybridSignature


@dataclass
class TransactionReceipt:
    """v1.1 atomic multi-party receipt binding terms to agent identities."""
    version: int  # = PROTOCOL_VERSION
    transaction_id: str
    created_at: int
    terms_schema_uri: str
    terms_canonical_json: bytes
    parties: list[ReceiptParty]
    party_signatures: list[ReceiptPartySignature] = field(default_factory=list)


@dataclass
class TransactionReceiptResult:
    """Outcome of verify_transaction_receipt(). Always check `valid` first."""
    valid: bool
    error_reason: str = ""
    party_results: list[VerifyResult] = field(default_factory=list)


@dataclass
class StreamContext:
    """Verifier state tracked per stream_id for v1.1 stream-bound bundles.

    ``last_seen_seq`` is the highest sequence number the verifier has already
    accepted for ``stream_id``; zero means no turns accepted yet, so the
    first valid bundle must carry ``stream_seq == 1``.
    """
    stream_id: bytes
    last_seen_seq: int = 0


@dataclass
class VerifyOptions:
    """Configures verify_bundle() beyond cryptographic basics."""
    required_scope: str = ""
    is_revoked: Optional[Callable[[str], bool]] = None
    # Force a fresh revocation check for high-stakes endpoints. The SDK cannot
    # fetch revocation state itself; callers must provide is_revoked when true.
    force_revocation_check: bool = False
    now: Optional[int] = None  # unix seconds; None = time.time()
    # Optional verifier-reconstructed 32-byte v1.1 session context.
    session_context: bytes = b""
    # Optional verifier-tracked v1.1 stream context. When set, bundles MUST
    # carry stream_id matching stream.stream_id and stream_seq equal to
    # stream.last_seen_seq+1.
    stream: Optional[StreamContext] = None
    # Application inputs for evaluating first-class constraints. Zero value
    # is fine for certs with no constraints; constraint-bearing certs fail
    # closed if required context is missing.
    context: Optional[VerifierContext] = None
