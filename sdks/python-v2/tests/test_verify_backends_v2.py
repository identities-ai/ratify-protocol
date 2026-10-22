"""The native and pure-Python hybrid verifiers must agree on every signature
in the shared corpus.

Native verification is the default and the pure-Python verifier is the
fallback for verify-only installs, so a vector one accepts and the other
rejects would make a verdict depend on how the SDK was installed. This test
runs the signature-corpus consumers (objects, object negatives, hedged
signatures, delegation and key-rotation signature vectors, cross-SDK
fixtures, and the strict-encoding crypto tests) in a subprocess that records
every hybrid signature check, then replays each recorded check through both
verifiers and requires the same verdict and error class from both, equal to
the verdict the run itself observed.
"""
from __future__ import annotations

import os
import pickle
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

import base64
import json

from ratify_protocol_v2 import _native, signing_v2
from ratify_protocol_v2._testing import pure_python_verification
from ratify_protocol_v2.errors_v2 import V2Error
from ratify_protocol_v2.signing_v2 import verify_v2_statement
from ratify_protocol_v2.types import HybridPublicKey, HybridSignature

from corpus import load

TESTS = Path(__file__).resolve().parent

SIGNATURE_CORPUS_MODULES = [
    "test_v2_conformance.py",  # objects, object-negatives, delegation and key-rotation signatures, logs
    "test_hedged_signatures_v2.py",  # hedged-signatures.json
    "test_cross_sdk_v2.py",  # cross-sdk/*.json from every SDK
    "test_crypto_v2.py",  # strict Ed25519 encodings and component lengths
    "test_archival_v2.py",
    "test_archival_signer_digest_v2.py",  # archival.json, external-signer.json, digest-functions.json
    "test_transaction_verification_v2.py",
]

pytestmark = pytest.mark.skipif(
    not _native.AVAILABLE or not signing_v2.native_verify_enabled(),
    reason="compares the native verifier with the pure-Python fallback; needs the extension",
)


@pytest.fixture(scope="module")
def recorded(tmp_path_factory):
    out = tmp_path_factory.mktemp("verify-record") / "records.pickle"
    env = dict(os.environ, RATIFY_V2_RECORD_VERIFY=str(out))
    env.pop("RATIFY_V2_PURE_VERIFY", None)
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x",
         *[str(TESTS / m) for m in SIGNATURE_CORPUS_MODULES]],
        cwd=TESTS.parent, env=env, capture_output=True, text=True,
    )
    assert run.returncode == 0, run.stdout[-4000:] + run.stderr[-4000:]
    with open(out, "rb") as fh:
        return pickle.load(fh)


def _verdict(code, signable, sig_ed, sig_ml, pub_ed, pub_ml) -> str:
    try:
        verify_v2_statement(
            code, signable,
            HybridSignature(ed25519=sig_ed, ml_dsa_65=sig_ml),
            HybridPublicKey(ed25519=pub_ed, ml_dsa_65=pub_ml),
        )
    except V2Error as exc:
        return exc.error_class
    return "ok"


def test_recording_covers_the_signature_corpus(recorded):
    verdicts = Counter(recorded.values())
    codes = {key[0] for key in recorded}
    # Every registered object type, accepted and rejected signatures alike.
    assert codes >= set(range(0x0001, 0x000A)), sorted(codes)
    assert verdicts["ok"] >= 50, verdicts
    assert verdicts["invalid_signature"] >= 20, verdicts


# Corpus negatives where only the strict Ed25519 rules reject the signature;
# a lax verifier (cofactored, or accepting S >= L or small-order points)
# would accept some of them. Each must have reached the verifier.
STRICT_ED25519_NEGATIVES = {
    "delegation_certificate/ed25519_s_plus_order": "signature",
    "delegation_certificate/ed25519_identity_r": "signature",
    "delegation_certificate/ed25519_identity_public_key": "issuer_pub_key",
    "delegation_certificate/ed25519_noncanonical_public_key": "issuer_pub_key",
    "delegation_certificate/ed25519_mixed_order_public_key": "issuer_pub_key",
}


def test_recording_includes_the_strict_ed25519_negatives(recorded):
    vectors = {v["name"]: v for v in load("object-negatives.json")["vectors"]}
    for name, member in STRICT_ED25519_NEGATIVES.items():
        obj = json.loads(base64.b64decode(vectors[name]["wire_b64"]))
        value = base64.b64decode(obj[member]["ed25519"])
        index = 2 if member == "signature" else 4  # sig_ed or pub_ed in a record key
        hits = [verdict for key, verdict in recorded.items() if key[0] == 0x0001 and key[index] == value]
        assert hits and set(hits) == {"invalid_signature"}, (name, hits)


def test_native_and_pure_verifiers_agree_on_every_recorded_signature(recorded):
    mismatches = []
    for key, observed in recorded.items():
        native = _verdict(*key)
        with pure_python_verification():
            assert not signing_v2.native_verify_enabled()
            pure = _verdict(*key)
        if not native == pure == observed:
            mismatches.append((key[0], len(key[1]), observed, native, pure))
    assert not mismatches, mismatches[:20]


def test_native_and_pure_verifiers_agree_on_single_faults(recorded):
    """Flip one bit in each component of accepted signatures and keys, and in
    the signed bytes; both verifiers must reject every variant identically."""
    accepted = [key for key, verdict in recorded.items() if verdict == "ok"]
    by_code = {}
    for key in accepted:
        by_code.setdefault(key[0], key)
    checked = 0
    for key in by_code.values():
        for index in range(1, 6):  # signable, sig_ed, sig_ml, pub_ed, pub_ml
            for position in (0, len(key[index]) // 2, len(key[index]) - 1):
                if not key[index]:
                    continue
                mutated = bytearray(key[index])
                mutated[position] ^= 0x01
                variant = key[:index] + (bytes(mutated),) + key[index + 1:]
                native = _verdict(*variant)
                with pure_python_verification():
                    pure = _verdict(*variant)
                assert native == pure == "invalid_signature", (key[0], index, position, native, pure)
                checked += 1
    assert checked >= 9 * 5 * 3 - 5


def test_pure_verify_environment_variable_selects_the_fallback(recorded):
    """RATIFY_V2_PURE_VERIFY=1 is the documented switch to the pure-Python
    verifier; it must take effect at import and still verify correctly."""
    key = next(k for k, v in recorded.items() if v == "ok")
    script = (
        "import pickle, sys\n"
        "from ratify_protocol_v2 import signing_v2\n"
        "from ratify_protocol_v2.types import HybridPublicKey, HybridSignature\n"
        "code, signable, sig_ed, sig_ml, pub_ed, pub_ml = pickle.loads(sys.stdin.buffer.read())\n"
        "signing_v2.verify_v2_statement(code, signable, HybridSignature(sig_ed, sig_ml), HybridPublicKey(pub_ed, pub_ml))\n"
        "print(signing_v2.native_verify_enabled())\n"
    )
    for value, expected in (("1", "False"), ("", "True")):
        env = dict(os.environ, RATIFY_V2_PURE_VERIFY=value)
        run = subprocess.run([sys.executable, "-c", script], input=pickle.dumps(key), env=env,
                             capture_output=True, cwd=TESTS.parent)
        assert run.returncode == 0, run.stderr.decode()
        assert run.stdout.decode().strip() == expected
