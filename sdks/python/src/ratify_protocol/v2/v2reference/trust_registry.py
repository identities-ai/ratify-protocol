"""In-memory REFERENCE candidate-record trust registry (mirrors Go
v2reference/trust_registry.go). TEST AND CONFORMANCE USE ONLY: it shows the
fail-closed resolution rule of SPEC-v2 §6.1; a deployment loads its records
from its own authenticated configuration."""
from __future__ import annotations

from ..signing_v2 import key_id_v2
from ..types import HybridPublicKey
from ..verify_v2 import V2_TRUST_AMBIGUOUS, V2_TRUST_TRUSTED, V2_TRUST_UNTRUSTED, V2TrustResolution


class TrustRegistry:
    """Holds caller-authenticated root records (complete hybrid public keys)
    and resolves a verified chain by its terminal issuer:

    - a record is a candidate when its key ID equals the terminal issuer ID or
      either of its components equals the matching component of the terminal
      issuer key;
    - no candidate is untrusted;
    - more than one candidate, including the same key configured twice, is
      ambiguous; the resolver never selects a first match;
    - exactly one candidate is trusted with that record's complete key, which
      the verifier then compares with the chain root (a partial match is
      treated as ambiguous there).
    """

    def __init__(self, records):
        self._records: list = []
        self._ids: list = []
        for i, key in enumerate(records):
            try:
                key_id = key_id_v2(key)
            except ValueError as exc:
                raise ValueError(f"v2reference: trust record {i}: {exc}") from exc
            self._records.append(HybridPublicKey(ed25519=bytes(key.ed25519), ml_dsa_65=bytes(key.ml_dsa_65)))
            self._ids.append(key_id)

    def resolve(self, ctx, chain) -> V2TrustResolution:
        """Implements the V2VerifyCallbacks.trust provider."""
        if not chain:
            return V2TrustResolution(outcome=V2_TRUST_UNTRUSTED)
        root = chain[-1]
        match = -1
        for i, key in enumerate(self._records):
            if (self._ids[i] != root.issuer_id and key.ed25519 != bytes(root.issuer_pub_key.ed25519)
                    and key.ml_dsa_65 != bytes(root.issuer_pub_key.ml_dsa_65)):
                continue
            if match >= 0:
                return V2TrustResolution(outcome=V2_TRUST_AMBIGUOUS)
            match = i
        if match < 0:
            return V2TrustResolution(outcome=V2_TRUST_UNTRUSTED)
        key = self._records[match]
        return V2TrustResolution(outcome=V2_TRUST_TRUSTED, root_key=HybridPublicKey(ed25519=key.ed25519, ml_dsa_65=key.ml_dsa_65))
