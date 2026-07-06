"""Canonical scope vocabulary for Ratify Protocol v1.

MUST stay in lock-step with Go's scope.go, TS's scope.ts, and Rust's scope.rs.
"""
from __future__ import annotations


# --- Meeting scopes ---
SCOPE_MEETING_ATTEND = "meeting:attend"
SCOPE_MEETING_SPEAK = "meeting:speak"
SCOPE_MEETING_VIDEO = "meeting:video"
SCOPE_MEETING_CHAT = "meeting:chat"
SCOPE_MEETING_SHARE_SCREEN = "meeting:share_screen"
SCOPE_MEETING_RECORD = "meeting:record"  # sensitive

# --- Communication scopes ---
SCOPE_COMMS_MESSAGE_READ = "comms:message:read"
SCOPE_COMMS_MESSAGE_SEND = "comms:message:send"
SCOPE_COMMS_MESSAGE_DELETE = "comms:message:delete"  # sensitive
SCOPE_COMMS_EMAIL_READ = "comms:email:read"
SCOPE_COMMS_EMAIL_SEND = "comms:email:send"
SCOPE_COMMS_EMAIL_DELETE = "comms:email:delete"  # sensitive
SCOPE_COMMS_CALENDAR_READ = "comms:calendar:read"
SCOPE_COMMS_CALENDAR_WRITE = "comms:calendar:write"

# --- File scopes ---
SCOPE_FILES_READ = "files:read"
SCOPE_FILES_WRITE = "files:write"  # sensitive

# --- Identity scopes ---
SCOPE_IDENTITY_PROVE = "identity:prove"
SCOPE_IDENTITY_DELEGATE = "identity:delegate"  # sensitive

# --- Presence scopes ---
# SCOPE_PRESENCE_REPRESENT: (sensitive) the agent is authorized to attend
# and interact as a direct representative of the principal — other parties
# in the interaction may be interacting with this agent as if it were the
# principal. Covers both non-likeness representatives and full likeness
# agents (Tavus, HeyGen, etc.).
#
# Distinct from generate:deepfake (content generation, not real-time
# representation) and identity:delegate (key delegation). Does NOT imply
# identity:prove — issuers grant both explicitly when both are needed;
# scope lists are literal, with no implication table.
#
# Verifiers accepting this scope are expected to surface the
# representation relationship to the other participants. That disclosure
# is platform policy, not a protocol constraint — see SPEC §9.1.
SCOPE_PRESENCE_REPRESENT = "presence:represent"  # sensitive

# --- Transaction scopes (v1, core to the "transaction horizon" thesis) ---
SCOPE_TRANSACT_PURCHASE = "transact:purchase"
SCOPE_TRANSACT_SELL = "transact:sell"
SCOPE_PAYMENTS_SEND = "payments:send"
SCOPE_PAYMENTS_RECEIVE = "payments:receive"
SCOPE_PAYMENTS_AUTHORIZE = "payments:authorize"  # sensitive

# --- Contract scopes ---
SCOPE_CONTRACT_READ = "contract:read"
SCOPE_CONTRACT_SIGN = "contract:sign"  # sensitive

# --- Data scopes (structured application data, distinct from files) ---
SCOPE_DATA_READ = "data:read"
SCOPE_DATA_WRITE = "data:write"  # sensitive
SCOPE_DATA_DELETE = "data:delete"  # sensitive
SCOPE_DATA_EXPORT = "data:export"  # sensitive — exfiltration concern
SCOPE_DATA_SHARE = "data:share"

# --- Execute scopes ---
SCOPE_EXECUTE_TOOL = "execute:tool"
SCOPE_EXECUTE_CODE = "execute:code"  # sensitive

# --- Generate scopes (AI content generation on someone's behalf) ---
SCOPE_GENERATE_CONTENT = "generate:content"
# Sensitive by policy: any "imitate a real person" generation creates
# an auditable explicit authorization trail.
SCOPE_GENERATE_DEEPFAKE = "generate:deepfake"  # sensitive

# --- Physical-world scopes (v1, first-class coverage for embodied agents) ---
# Ratify is channel-agnostic: same cert/bundle/verify semantics for software
# agents and for robots, drones, vehicles, infrastructure controllers.
# Location / time / speed / amount / rate bounds live in first-class
# Constraint objects on DelegationCert (see types.py).

SCOPE_PHYSICAL_ENTER = "physical:enter"
SCOPE_PHYSICAL_EXIT = "physical:exit"
SCOPE_PHYSICAL_ACTUATE = "physical:actuate"  # sensitive
SCOPE_PHYSICAL_MANIPULATE = "physical:manipulate"  # sensitive

SCOPE_ROBOT_OPERATE = "robot:operate"
SCOPE_ROBOT_MOVE = "robot:move"
SCOPE_ROBOT_INTERACT = "robot:interact"

SCOPE_DRONE_FLY = "drone:fly"  # sensitive
SCOPE_DRONE_DELIVER = "drone:deliver"
SCOPE_DRONE_CAPTURE = "drone:capture"

SCOPE_VEHICLE_OPERATE = "vehicle:operate"  # sensitive
SCOPE_VEHICLE_TRANSPORT = "vehicle:transport"
SCOPE_VEHICLE_CHARGE = "vehicle:charge"

SCOPE_INFRASTRUCTURE_MONITOR = "infrastructure:monitor"
SCOPE_INFRASTRUCTURE_CONTROL = "infrastructure:control"  # sensitive
SCOPE_INFRASTRUCTURE_ACCESS = "infrastructure:access"  # sensitive

SCOPE_ACTUATE_VALVE = "actuate:valve"  # sensitive
SCOPE_ACTUATE_MOTOR = "actuate:motor"  # sensitive
SCOPE_ACTUATE_SWITCH = "actuate:switch"  # sensitive

# --- Extension pattern ---
# Any scope string starting with CUSTOM_SCOPE_PREFIX is accepted by
# validate_scopes, passes through expand_scopes unchanged, and is treated as
# non-sensitive unless the application opts in via out-of-band policy.
#
# Example: "custom:acme:inventory:read"
CUSTOM_SCOPE_PREFIX = "custom:"


_SENSITIVE_SCOPES: frozenset[str] = frozenset({
    SCOPE_MEETING_RECORD,
    SCOPE_COMMS_MESSAGE_DELETE,
    SCOPE_COMMS_EMAIL_DELETE,
    SCOPE_FILES_WRITE,
    SCOPE_IDENTITY_DELEGATE,
    SCOPE_PRESENCE_REPRESENT,
    SCOPE_PAYMENTS_AUTHORIZE,
    SCOPE_CONTRACT_SIGN,
    SCOPE_DATA_WRITE,
    SCOPE_DATA_DELETE,
    SCOPE_DATA_EXPORT,
    SCOPE_EXECUTE_CODE,
    SCOPE_GENERATE_DEEPFAKE,
    SCOPE_PHYSICAL_ACTUATE,
    SCOPE_PHYSICAL_MANIPULATE,
    SCOPE_DRONE_FLY,
    SCOPE_VEHICLE_OPERATE,
    SCOPE_INFRASTRUCTURE_CONTROL,
    SCOPE_INFRASTRUCTURE_ACCESS,
    SCOPE_ACTUATE_VALVE,
    SCOPE_ACTUATE_MOTOR,
    SCOPE_ACTUATE_SWITCH,
})

_VALID_SCOPES: frozenset[str] = frozenset({
    SCOPE_MEETING_ATTEND,
    SCOPE_MEETING_SPEAK,
    SCOPE_MEETING_VIDEO,
    SCOPE_MEETING_CHAT,
    SCOPE_MEETING_SHARE_SCREEN,
    SCOPE_MEETING_RECORD,
    SCOPE_COMMS_MESSAGE_READ,
    SCOPE_COMMS_MESSAGE_SEND,
    SCOPE_COMMS_MESSAGE_DELETE,
    SCOPE_COMMS_EMAIL_READ,
    SCOPE_COMMS_EMAIL_SEND,
    SCOPE_COMMS_EMAIL_DELETE,
    SCOPE_COMMS_CALENDAR_READ,
    SCOPE_COMMS_CALENDAR_WRITE,
    SCOPE_FILES_READ,
    SCOPE_FILES_WRITE,
    SCOPE_IDENTITY_PROVE,
    SCOPE_IDENTITY_DELEGATE,
    SCOPE_PRESENCE_REPRESENT,
    SCOPE_TRANSACT_PURCHASE,
    SCOPE_TRANSACT_SELL,
    SCOPE_PAYMENTS_SEND,
    SCOPE_PAYMENTS_RECEIVE,
    SCOPE_PAYMENTS_AUTHORIZE,
    SCOPE_CONTRACT_READ,
    SCOPE_CONTRACT_SIGN,
    SCOPE_DATA_READ,
    SCOPE_DATA_WRITE,
    SCOPE_DATA_DELETE,
    SCOPE_DATA_EXPORT,
    SCOPE_DATA_SHARE,
    SCOPE_EXECUTE_TOOL,
    SCOPE_EXECUTE_CODE,
    SCOPE_GENERATE_CONTENT,
    SCOPE_GENERATE_DEEPFAKE,
    SCOPE_PHYSICAL_ENTER,
    SCOPE_PHYSICAL_EXIT,
    SCOPE_PHYSICAL_ACTUATE,
    SCOPE_PHYSICAL_MANIPULATE,
    SCOPE_ROBOT_OPERATE,
    SCOPE_ROBOT_MOVE,
    SCOPE_ROBOT_INTERACT,
    SCOPE_DRONE_FLY,
    SCOPE_DRONE_DELIVER,
    SCOPE_DRONE_CAPTURE,
    SCOPE_VEHICLE_OPERATE,
    SCOPE_VEHICLE_TRANSPORT,
    SCOPE_VEHICLE_CHARGE,
    SCOPE_INFRASTRUCTURE_MONITOR,
    SCOPE_INFRASTRUCTURE_CONTROL,
    SCOPE_INFRASTRUCTURE_ACCESS,
    SCOPE_ACTUATE_VALVE,
    SCOPE_ACTUATE_MOTOR,
    SCOPE_ACTUATE_SWITCH,
})

# Wildcards expand ONLY to non-sensitive scopes.
_SCOPE_WILDCARDS: dict[str, tuple[str, ...]] = {
    "meeting:*": (
        SCOPE_MEETING_ATTEND,
        SCOPE_MEETING_SPEAK,
        SCOPE_MEETING_VIDEO,
        SCOPE_MEETING_CHAT,
        SCOPE_MEETING_SHARE_SCREEN,
    ),
    "comms:message:*": (SCOPE_COMMS_MESSAGE_READ, SCOPE_COMMS_MESSAGE_SEND),
    "comms:email:*": (SCOPE_COMMS_EMAIL_READ, SCOPE_COMMS_EMAIL_SEND),
    "comms:*": (
        SCOPE_COMMS_MESSAGE_READ,
        SCOPE_COMMS_MESSAGE_SEND,
        SCOPE_COMMS_EMAIL_READ,
        SCOPE_COMMS_EMAIL_SEND,
        SCOPE_COMMS_CALENDAR_READ,
        SCOPE_COMMS_CALENDAR_WRITE,
    ),
    "transact:*": (SCOPE_TRANSACT_PURCHASE, SCOPE_TRANSACT_SELL),
    "payments:*": (SCOPE_PAYMENTS_SEND, SCOPE_PAYMENTS_RECEIVE),
    "data:*": (SCOPE_DATA_READ, SCOPE_DATA_SHARE),
    "execute:*": (SCOPE_EXECUTE_TOOL,),
    "generate:*": (SCOPE_GENERATE_CONTENT,),
    "physical:*": (SCOPE_PHYSICAL_ENTER, SCOPE_PHYSICAL_EXIT),
    "robot:*": (SCOPE_ROBOT_OPERATE, SCOPE_ROBOT_MOVE, SCOPE_ROBOT_INTERACT),
    "drone:*": (SCOPE_DRONE_DELIVER, SCOPE_DRONE_CAPTURE),
    "vehicle:*": (SCOPE_VEHICLE_TRANSPORT, SCOPE_VEHICLE_CHARGE),
    "infrastructure:*": (SCOPE_INFRASTRUCTURE_MONITOR,),
    # actuate:* — every member sensitive; NO wildcard expansion.
    # presence:* — presence:represent is sensitive, so NO wildcard expansion.
    # Representation must always be granted explicitly.
}


def _is_custom_scope(s: str) -> bool:
    return s.startswith(CUSTOM_SCOPE_PREFIX) and len(s) > len(CUSTOM_SCOPE_PREFIX)


def validate_scopes(scopes: list[str]) -> str | None:
    """Return an error message if any scope is invalid; None if all valid.

    Custom scopes (prefix "custom:") are accepted as valid extensions.
    """
    for s in scopes:
        if s in _VALID_SCOPES:
            continue
        if s in _SCOPE_WILDCARDS:
            continue
        if _is_custom_scope(s):
            continue
        return f'unknown scope "{s}": not in canonical vocabulary and not a custom: extension'
    return None


def is_sensitive(scope: str) -> bool:
    """True if the scope is flagged as sensitive. Custom scopes are
    non-sensitive by default; applications may enforce policy out-of-band."""
    return scope in _SENSITIVE_SCOPES


def expand_scopes(scopes: list[str]) -> list[str]:
    """Replace wildcards with their constituent non-sensitive scopes.

    Deduplicates and returns results lex-sorted for deterministic output.
    Custom scopes pass through unchanged.
    """
    seen: set[str] = set()
    for s in scopes:
        children = _SCOPE_WILDCARDS.get(s)
        if children is not None:
            seen.update(children)
        else:
            seen.add(s)
    return sorted(seen)


def has_scope(granted: list[str], required: str) -> bool:
    """True iff `required` is present after wildcard expansion of `granted`."""
    return required in expand_scopes(granted)


def intersect_scopes(*lists: list[str]) -> list[str]:
    """Set of scopes in every input list after wildcard expansion. Lex-sorted."""
    if not lists:
        return []
    effective = set(expand_scopes(lists[0]))
    for lst in lists[1:]:
        effective &= set(expand_scopes(lst))
    return sorted(effective)
