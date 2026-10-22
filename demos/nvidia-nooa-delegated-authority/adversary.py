# SPDX-License-Identifier: Apache-2.0
"""Hand-built presentations an attacker could send. Test and harness use only.

The v2 SDK refuses to sign a proof bundle whose agent key does not match the
leaf delegation subject, or whose signing key is not the agent it names. That
protects honest callers; it does not constrain an attacker, who is not obliged
to use the SDK. The adversarial cases therefore build and sign the wire by
hand here, and the tests assert that the *receiver* refuses what arrives.

Nothing in the agent's own code path imports this module.
"""

from __future__ import annotations

from ratify_protocol_v2 import background
from ratify_protocol_v2.protocol_v2 import (
    ProofBundleV2,
    decode_proof_bundle_v2,
    delegation_digest_v2,
    encode_proof_bundle_v2,
    placeholder_signature_v2,
    presentation_signable_bytes_v2,
)
from ratify_protocol_v2.signing_v2 import (
    CHALLENGE_PRESENTATION,
    _as_signer,
    _sign_v2_statement_with_signer,
    signer_public_key_v2,
)


def forge_presentation(
    *, verifier_id, agent_id, agent_pub, signing_priv, delegations, challenge,
    challenge_at, session_context,
) -> bytes:
    """Sign a v2 proof bundle with ``signing_priv`` and no consistency checks.

    Returns the exact wire bytes. Every structural and signature check is left
    to the verifier under test."""
    unsigned = ProofBundleV2(
        version=2,
        verifier_id=verifier_id,
        agent_id=agent_id,
        agent_pub_key=agent_pub,
        delegations=list(delegations),
        delegation_digest=bytes(48),
        challenge=challenge,
        challenge_at=challenge_at,
        challenge_sig=placeholder_signature_v2(),
        session_context=session_context,
    )
    prepared = decode_proof_bundle_v2(encode_proof_bundle_v2(unsigned))
    prepared.delegation_digest = delegation_digest_v2(prepared.delegations)
    signer = _as_signer(signing_priv)
    prepared.challenge_sig = _sign_v2_statement_with_signer(
        background(),
        CHALLENGE_PRESENTATION,
        presentation_signable_bytes_v2(prepared),
        signer,
        signer_public_key_v2(signer),
    )
    return encode_proof_bundle_v2(prepared)
