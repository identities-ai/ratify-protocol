import json
from pathlib import Path

import pytest
import accelerator
from ratify_protocol import StreamContext, VerifierContext, VerifyOptions, base64_standard_decode, decode_proof_bundle
from ratify_rust_accel import verify_bundle_json, verify_bundle_object

VECTORS = Path(__file__).resolve().parents[2] / "testvectors" / "v1"
RESULT_FIELDS = (
    "valid",
    "identity_status",
    "human_id",
    "agent_id",
    "granted_scope",
    "error_reason",
)


def native_options(fixture):
    options = dict(fixture["expected"]["verify_options"])
    if fixture.get("verifier_context") is not None:
        options["context"] = fixture["verifier_context"]
    expected = fixture["expected"]["verify_result"]
    if expected.get("identity_status") == "revoked" and len(fixture["bundle"]["delegations"]) > 1:
        options["revoked_cert_ids"] = [fixture["bundle"]["delegations"][1]["cert_id"]]
    return options


def python_options(fixture, bundle):
    raw = fixture["expected"]["verify_options"]
    context = fixture.get("verifier_context")
    verifier_context = None
    if context is not None:
        count = context.get("invocations_in_window_count")
        verifier_context = VerifierContext(
            current_lat=context.get("current_lat"), current_lon=context.get("current_lon"),
            current_alt_m=context.get("current_alt_m"), current_speed_mps=context.get("current_speed_mps"),
            requested_amount=context.get("requested_amount"), requested_currency=context.get("requested_currency"),
            invocations_in_window=(lambda _cert, _window, n=count: n) if count is not None else None,
            requested_resource_id=context.get("requested_resource_id") or "",
            requested_path=context.get("requested_path") or "",
            has_resource=bool(context.get("requested_resource_id")),
        )
    revocation = None
    expected = fixture["expected"]["verify_result"]
    if expected.get("identity_status") == "revoked" and len(bundle.delegations) > 1:
        revoked_id = bundle.delegations[1].cert_id
        revocation = type("Revocation", (), {"is_revoked": lambda self, cert_id: (cert_id == revoked_id, None)})()
    stream = raw.get("stream")
    return VerifyOptions(
        required_scope=raw.get("required_scope", ""), now=raw["now"], revocation=revocation,
        session_context=base64_standard_decode(raw["session_context"]) if raw.get("session_context") else b"",
        stream=StreamContext(base64_standard_decode(stream["stream_id"]), stream.get("last_seen_seq", 0)) if stream else None,
        context=verifier_context,
    )


def verify_vectors():
    for path in sorted(VECTORS.glob("*.json")):
        fixture = json.loads(path.read_text())
        expected = fixture.get("expected", {})
        if fixture.get("bundle") and expected.get("verify_options") and expected.get("verify_result"):
            yield path.name, fixture


@pytest.mark.parametrize("name,fixture", list(verify_vectors()))
def test_native_matches_conformance_result(name, fixture):
    bundle_json = json.dumps(fixture["bundle"], separators=(",", ":"))
    options_json = json.dumps(native_options(fixture), separators=(",", ":"))
    result = json.loads(verify_bundle_json(bundle_json, options_json))
    object_result = json.loads(verify_bundle_object(decode_proof_bundle(bundle_json), options_json))
    bundle = decode_proof_bundle(bundle_json)
    accelerated = accelerator.verify_bundle(bundle, python_options(fixture, bundle))
    expected = fixture["expected"]["verify_result"]
    for field in RESULT_FIELDS:
        default = [] if field == "granted_scope" else ""
        assert result.get(field, default) == expected.get(field, default), f"{name}: {field}"
        assert object_result.get(field, default) == expected.get(field, default), f"{name}: object {field}"
        assert getattr(accelerated, field) == expected.get(field, default), f"{name}: routed {field}"


@pytest.mark.parametrize("bundle,options", [("{}", "{}"), ("not-json", "{}"), ("{}", '{"unknown":1}')])
def test_malformed_input_fails_without_terminating_python(bundle, options):
    with pytest.raises(ValueError):
        verify_bundle_json(bundle, options)
