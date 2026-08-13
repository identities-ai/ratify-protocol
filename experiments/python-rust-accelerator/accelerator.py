import base64
import json

from ratify_protocol import VerifyResult
from ratify_protocol import verify_bundle as python_verify_bundle

try:
    from ratify_rust_accel import verify_bundle_object as _native_verify_bundle_object
except (ImportError, OSError):
    _native_verify_bundle_object = None


def native_eligible(options):
    context = options.context
    return not any(
        (
            options.is_revoked,
            options.revocation,
            options.force_revocation_check,
            options.policy,
            options.audit,
            options.constraint_evaluators,
            options.policy_verdict,
            options.policy_secret,
            options.anchor_resolver,
            options.challenge_store,
            context is not None and context.invocations_in_window is not None,
        )
    )


def _options_json(options):
    context = options.context
    context_dict = {}
    if context is not None:
        context_dict = {
            "current_lat": context.current_lat,
            "current_lon": context.current_lon,
            "current_alt_m": context.current_alt_m,
            "current_speed_mps": context.current_speed_mps,
            "requested_amount": context.requested_amount,
            "requested_currency": context.requested_currency,
            "requested_resource_id": context.requested_resource_id or None,
            "requested_path": context.requested_path or None,
        }
    stream = None
    if options.stream is not None:
        stream = {
            "stream_id": base64.b64encode(options.stream.stream_id).decode("ascii"),
            "last_seen_seq": options.stream.last_seen_seq,
        }
    return json.dumps(
        {
            "required_scope": options.required_scope,
            "now": options.now,
            "session_context": base64.b64encode(options.session_context).decode("ascii"),
            "stream": stream,
            "context": context_dict,
        },
        separators=(",", ":"),
    )


def verify_bundle(bundle, options):
    if _native_verify_bundle_object is None or not native_eligible(options):
        return python_verify_bundle(bundle, options)
    try:
        result = json.loads(_native_verify_bundle_object(bundle, _options_json(options)))
    except (TypeError, ValueError):
        return python_verify_bundle(bundle, options)
    return VerifyResult(
        valid=result["valid"],
        identity_status=result["identity_status"],
        human_id=result.get("human_id", ""),
        agent_id=result.get("agent_id", ""),
        agent_name=result.get("agent_name", ""),
        agent_type=result.get("agent_type", ""),
        granted_scope=result.get("granted_scope", []),
        error_reason=result.get("error_reason", ""),
    )
