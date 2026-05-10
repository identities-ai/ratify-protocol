//! Canonical scope vocabulary for Ratify Protocol v1.
//!
//! MUST stay in lock-step with Go's scope.go, TS's scope.ts, and Python's scope.py.

// --- Meeting scopes ---
pub const SCOPE_MEETING_ATTEND: &str = "meeting:attend";
pub const SCOPE_MEETING_SPEAK: &str = "meeting:speak";
pub const SCOPE_MEETING_VIDEO: &str = "meeting:video";
pub const SCOPE_MEETING_CHAT: &str = "meeting:chat";
pub const SCOPE_MEETING_SHARE_SCREEN: &str = "meeting:share_screen";
pub const SCOPE_MEETING_RECORD: &str = "meeting:record"; // sensitive

// --- Communication scopes ---
pub const SCOPE_COMMS_MESSAGE_READ: &str = "comms:message:read";
pub const SCOPE_COMMS_MESSAGE_SEND: &str = "comms:message:send";
pub const SCOPE_COMMS_MESSAGE_DELETE: &str = "comms:message:delete"; // sensitive
pub const SCOPE_COMMS_EMAIL_READ: &str = "comms:email:read";
pub const SCOPE_COMMS_EMAIL_SEND: &str = "comms:email:send";
pub const SCOPE_COMMS_EMAIL_DELETE: &str = "comms:email:delete"; // sensitive
pub const SCOPE_COMMS_CALENDAR_READ: &str = "comms:calendar:read";
pub const SCOPE_COMMS_CALENDAR_WRITE: &str = "comms:calendar:write";

// --- File scopes ---
pub const SCOPE_FILES_READ: &str = "files:read";
pub const SCOPE_FILES_WRITE: &str = "files:write"; // sensitive

// --- Identity scopes ---
pub const SCOPE_IDENTITY_PROVE: &str = "identity:prove";
pub const SCOPE_IDENTITY_DELEGATE: &str = "identity:delegate"; // sensitive

// --- Transaction scopes (v1, core to the "transaction horizon" thesis) ---
pub const SCOPE_TRANSACT_PURCHASE: &str = "transact:purchase";
pub const SCOPE_TRANSACT_SELL: &str = "transact:sell";
pub const SCOPE_PAYMENTS_SEND: &str = "payments:send";
pub const SCOPE_PAYMENTS_RECEIVE: &str = "payments:receive";
pub const SCOPE_PAYMENTS_AUTHORIZE: &str = "payments:authorize"; // sensitive

// --- Contract scopes ---
pub const SCOPE_CONTRACT_READ: &str = "contract:read";
pub const SCOPE_CONTRACT_SIGN: &str = "contract:sign"; // sensitive

// --- Data scopes (structured application data, distinct from files) ---
pub const SCOPE_DATA_READ: &str = "data:read";
pub const SCOPE_DATA_WRITE: &str = "data:write"; // sensitive
pub const SCOPE_DATA_DELETE: &str = "data:delete"; // sensitive
pub const SCOPE_DATA_EXPORT: &str = "data:export"; // sensitive — exfiltration
pub const SCOPE_DATA_SHARE: &str = "data:share";

// --- Execute scopes ---
pub const SCOPE_EXECUTE_TOOL: &str = "execute:tool";
pub const SCOPE_EXECUTE_CODE: &str = "execute:code"; // sensitive

// --- Generate scopes (AI content generation on someone's behalf) ---
pub const SCOPE_GENERATE_CONTENT: &str = "generate:content";
// Sensitive by policy: any "imitate a real person" generation creates
// an auditable explicit authorization trail.
pub const SCOPE_GENERATE_DEEPFAKE: &str = "generate:deepfake"; // sensitive

// --- Physical-world scopes (v1, first-class coverage for embodied agents) ---
// Ratify is channel-agnostic: same cert/bundle/verify semantics for software
// agents and for robots, drones, vehicles, infrastructure controllers.
// Location / time / speed / amount / rate bounds live in first-class
// Constraint objects on DelegationCert (see types.rs).

pub const SCOPE_PHYSICAL_ENTER: &str = "physical:enter";
pub const SCOPE_PHYSICAL_EXIT: &str = "physical:exit";
pub const SCOPE_PHYSICAL_ACTUATE: &str = "physical:actuate"; // sensitive
pub const SCOPE_PHYSICAL_MANIPULATE: &str = "physical:manipulate"; // sensitive

pub const SCOPE_ROBOT_OPERATE: &str = "robot:operate";
pub const SCOPE_ROBOT_MOVE: &str = "robot:move";
pub const SCOPE_ROBOT_INTERACT: &str = "robot:interact";

pub const SCOPE_DRONE_FLY: &str = "drone:fly"; // sensitive
pub const SCOPE_DRONE_DELIVER: &str = "drone:deliver";
pub const SCOPE_DRONE_CAPTURE: &str = "drone:capture";

pub const SCOPE_VEHICLE_OPERATE: &str = "vehicle:operate"; // sensitive
pub const SCOPE_VEHICLE_TRANSPORT: &str = "vehicle:transport";
pub const SCOPE_VEHICLE_CHARGE: &str = "vehicle:charge";

pub const SCOPE_INFRASTRUCTURE_MONITOR: &str = "infrastructure:monitor";
pub const SCOPE_INFRASTRUCTURE_CONTROL: &str = "infrastructure:control"; // sensitive
pub const SCOPE_INFRASTRUCTURE_ACCESS: &str = "infrastructure:access"; // sensitive

pub const SCOPE_ACTUATE_VALVE: &str = "actuate:valve"; // sensitive
pub const SCOPE_ACTUATE_MOTOR: &str = "actuate:motor"; // sensitive
pub const SCOPE_ACTUATE_SWITCH: &str = "actuate:switch"; // sensitive

// --- Extension pattern ---
/// Any scope string starting with CUSTOM_SCOPE_PREFIX is accepted by
/// validate_scopes, passes through expand_scopes unchanged, and is treated as
/// non-sensitive unless the application opts in via out-of-band policy.
///
/// Example: `"custom:acme:inventory:read"`
pub const CUSTOM_SCOPE_PREFIX: &str = "custom:";

fn sensitive_scopes() -> &'static [&'static str] {
    &[
        SCOPE_MEETING_RECORD,
        SCOPE_COMMS_MESSAGE_DELETE,
        SCOPE_COMMS_EMAIL_DELETE,
        SCOPE_FILES_WRITE,
        SCOPE_IDENTITY_DELEGATE,
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
    ]
}

fn valid_scopes() -> &'static [&'static str] {
    &[
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
    ]
}

fn wildcard_expansion(w: &str) -> Option<&'static [&'static str]> {
    match w {
        "meeting:*" => Some(&[
            SCOPE_MEETING_ATTEND,
            SCOPE_MEETING_SPEAK,
            SCOPE_MEETING_VIDEO,
            SCOPE_MEETING_CHAT,
            SCOPE_MEETING_SHARE_SCREEN,
        ]),
        "comms:message:*" => Some(&[SCOPE_COMMS_MESSAGE_READ, SCOPE_COMMS_MESSAGE_SEND]),
        "comms:email:*" => Some(&[SCOPE_COMMS_EMAIL_READ, SCOPE_COMMS_EMAIL_SEND]),
        "comms:*" => Some(&[
            SCOPE_COMMS_MESSAGE_READ,
            SCOPE_COMMS_MESSAGE_SEND,
            SCOPE_COMMS_EMAIL_READ,
            SCOPE_COMMS_EMAIL_SEND,
            SCOPE_COMMS_CALENDAR_READ,
            SCOPE_COMMS_CALENDAR_WRITE,
        ]),
        "transact:*" => Some(&[SCOPE_TRANSACT_PURCHASE, SCOPE_TRANSACT_SELL]),
        "payments:*" => Some(&[SCOPE_PAYMENTS_SEND, SCOPE_PAYMENTS_RECEIVE]),
        "data:*" => Some(&[SCOPE_DATA_READ, SCOPE_DATA_SHARE]),
        "execute:*" => Some(&[SCOPE_EXECUTE_TOOL]),
        "generate:*" => Some(&[SCOPE_GENERATE_CONTENT]),
        "physical:*" => Some(&[SCOPE_PHYSICAL_ENTER, SCOPE_PHYSICAL_EXIT]),
        "robot:*" => Some(&[SCOPE_ROBOT_OPERATE, SCOPE_ROBOT_MOVE, SCOPE_ROBOT_INTERACT]),
        "drone:*" => Some(&[SCOPE_DRONE_DELIVER, SCOPE_DRONE_CAPTURE]),
        "vehicle:*" => Some(&[SCOPE_VEHICLE_TRANSPORT, SCOPE_VEHICLE_CHARGE]),
        "infrastructure:*" => Some(&[SCOPE_INFRASTRUCTURE_MONITOR]),
        // actuate:* — every member sensitive; NO wildcard expansion.
        _ => None,
    }
}

fn is_custom_scope(s: &str) -> bool {
    s.starts_with(CUSTOM_SCOPE_PREFIX) && s.len() > CUSTOM_SCOPE_PREFIX.len()
}

/// Return an error message if any scope is invalid; None if all valid.
/// Custom scopes (prefix "custom:") are accepted as valid extensions.
pub fn validate_scopes(scopes: &[String]) -> Option<String> {
    for s in scopes {
        if valid_scopes().contains(&s.as_str()) {
            continue;
        }
        if wildcard_expansion(s).is_some() {
            continue;
        }
        if is_custom_scope(s) {
            continue;
        }
        return Some(format!(
            "unknown scope \"{}\": not in canonical vocabulary and not a custom: extension",
            s
        ));
    }
    None
}

/// True if the scope is flagged as sensitive. Custom scopes are non-sensitive
/// by default; applications may enforce policy out-of-band.
pub fn is_sensitive(scope: &str) -> bool {
    sensitive_scopes().contains(&scope)
}

/// Replace wildcard scopes with their constituent non-sensitive scopes.
/// Deduplicates and returns lex-sorted. Custom scopes pass through unchanged.
pub fn expand_scopes(scopes: &[String]) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    for s in scopes {
        if let Some(children) = wildcard_expansion(s) {
            for c in children {
                seen.insert((*c).to_string());
            }
        } else {
            seen.insert(s.clone());
        }
    }
    seen.into_iter().collect()
}

pub fn has_scope(granted: &[String], required: &str) -> bool {
    expand_scopes(granted).iter().any(|s| s == required)
}

/// Set of scopes in every input list after wildcard expansion. Lex-sorted.
pub fn intersect_scopes(lists: &[&[String]]) -> Vec<String> {
    if lists.is_empty() {
        return Vec::new();
    }
    let mut effective: std::collections::BTreeSet<String> =
        expand_scopes(lists[0]).into_iter().collect();
    for list in &lists[1..] {
        let expanded: std::collections::BTreeSet<String> =
            expand_scopes(list).into_iter().collect();
        effective = effective.intersection(&expanded).cloned().collect();
    }
    effective.into_iter().collect()
}
