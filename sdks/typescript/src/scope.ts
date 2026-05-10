// Canonical scope vocabulary for Ratify Protocol v1.
// MUST stay in lock-step with Go's scope.go, Python's scope.py, and Rust's scope.rs.

// --- Meeting scopes ---
export const SCOPE_MEETING_ATTEND = "meeting:attend";
export const SCOPE_MEETING_SPEAK = "meeting:speak";
export const SCOPE_MEETING_VIDEO = "meeting:video";
export const SCOPE_MEETING_CHAT = "meeting:chat";
export const SCOPE_MEETING_SHARE_SCREEN = "meeting:share_screen";
export const SCOPE_MEETING_RECORD = "meeting:record"; // sensitive

// --- Communication scopes ---
export const SCOPE_COMMS_MESSAGE_READ = "comms:message:read";
export const SCOPE_COMMS_MESSAGE_SEND = "comms:message:send";
export const SCOPE_COMMS_MESSAGE_DELETE = "comms:message:delete"; // sensitive
export const SCOPE_COMMS_EMAIL_READ = "comms:email:read";
export const SCOPE_COMMS_EMAIL_SEND = "comms:email:send";
export const SCOPE_COMMS_EMAIL_DELETE = "comms:email:delete"; // sensitive
export const SCOPE_COMMS_CALENDAR_READ = "comms:calendar:read";
export const SCOPE_COMMS_CALENDAR_WRITE = "comms:calendar:write";

// --- File scopes ---
export const SCOPE_FILES_READ = "files:read";
export const SCOPE_FILES_WRITE = "files:write"; // sensitive

// --- Identity scopes ---
export const SCOPE_IDENTITY_PROVE = "identity:prove";
export const SCOPE_IDENTITY_DELEGATE = "identity:delegate"; // sensitive

// --- Transaction scopes (v1, core to the "transaction horizon" thesis) ---
export const SCOPE_TRANSACT_PURCHASE = "transact:purchase";
export const SCOPE_TRANSACT_SELL = "transact:sell";
export const SCOPE_PAYMENTS_SEND = "payments:send";
export const SCOPE_PAYMENTS_RECEIVE = "payments:receive";
export const SCOPE_PAYMENTS_AUTHORIZE = "payments:authorize"; // sensitive

// --- Contract scopes ---
export const SCOPE_CONTRACT_READ = "contract:read";
export const SCOPE_CONTRACT_SIGN = "contract:sign"; // sensitive

// --- Data scopes (structured application data, distinct from files) ---
export const SCOPE_DATA_READ = "data:read";
export const SCOPE_DATA_WRITE = "data:write"; // sensitive
export const SCOPE_DATA_DELETE = "data:delete"; // sensitive
export const SCOPE_DATA_EXPORT = "data:export"; // sensitive — exfiltration concern
export const SCOPE_DATA_SHARE = "data:share";

// --- Execute scopes ---
export const SCOPE_EXECUTE_TOOL = "execute:tool";
export const SCOPE_EXECUTE_CODE = "execute:code"; // sensitive

// --- Generate scopes (AI content generation on someone's behalf) ---
export const SCOPE_GENERATE_CONTENT = "generate:content";
// Sensitive by policy: any "imitate a real person" generation creates
// an auditable explicit authorization trail.
export const SCOPE_GENERATE_DEEPFAKE = "generate:deepfake"; // sensitive

// --- Physical-world scopes (v1, first-class coverage for embodied agents) ---
// The entire Ratify design is channel-agnostic: the same cert/bundle/verify
// semantics that authorize a software agent also authorize a robot, drone,
// vehicle, or infrastructure controller. The scopes below are the canonical
// vocabulary for agents that take action in physical space. Location,
// temporal, and magnitude bounds live in first-class Constraint objects on
// the DelegationCert.

export const SCOPE_PHYSICAL_ENTER = "physical:enter";
export const SCOPE_PHYSICAL_EXIT = "physical:exit";
export const SCOPE_PHYSICAL_ACTUATE = "physical:actuate"; // sensitive
export const SCOPE_PHYSICAL_MANIPULATE = "physical:manipulate"; // sensitive

export const SCOPE_ROBOT_OPERATE = "robot:operate";
export const SCOPE_ROBOT_MOVE = "robot:move";
export const SCOPE_ROBOT_INTERACT = "robot:interact";

export const SCOPE_DRONE_FLY = "drone:fly"; // sensitive
export const SCOPE_DRONE_DELIVER = "drone:deliver";
export const SCOPE_DRONE_CAPTURE = "drone:capture";

export const SCOPE_VEHICLE_OPERATE = "vehicle:operate"; // sensitive
export const SCOPE_VEHICLE_TRANSPORT = "vehicle:transport";
export const SCOPE_VEHICLE_CHARGE = "vehicle:charge";

export const SCOPE_INFRASTRUCTURE_MONITOR = "infrastructure:monitor";
export const SCOPE_INFRASTRUCTURE_CONTROL = "infrastructure:control"; // sensitive
export const SCOPE_INFRASTRUCTURE_ACCESS = "infrastructure:access"; // sensitive

export const SCOPE_ACTUATE_VALVE = "actuate:valve"; // sensitive
export const SCOPE_ACTUATE_MOTOR = "actuate:motor"; // sensitive
export const SCOPE_ACTUATE_SWITCH = "actuate:switch"; // sensitive

// --- Extension pattern ---
/**
 * Any scope string starting with CUSTOM_SCOPE_PREFIX is accepted by
 * validateScopes, passes through expandScopes unchanged, and is treated as
 * non-sensitive unless the application opts in via out-of-band policy.
 *
 * Example: "custom:acme:inventory:read"
 */
export const CUSTOM_SCOPE_PREFIX = "custom:";

const SENSITIVE_SCOPES: ReadonlySet<string> = new Set([
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
]);

const VALID_SCOPES: ReadonlySet<string> = new Set([
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
]);

// Wildcards expand only to NON-sensitive scopes. Sensitive scopes always
// require explicit grant.
const SCOPE_WILDCARDS: Readonly<Record<string, readonly string[]>> = {
  "meeting:*": [
    SCOPE_MEETING_ATTEND,
    SCOPE_MEETING_SPEAK,
    SCOPE_MEETING_VIDEO,
    SCOPE_MEETING_CHAT,
    SCOPE_MEETING_SHARE_SCREEN,
  ],
  "comms:message:*": [SCOPE_COMMS_MESSAGE_READ, SCOPE_COMMS_MESSAGE_SEND],
  "comms:email:*": [SCOPE_COMMS_EMAIL_READ, SCOPE_COMMS_EMAIL_SEND],
  "comms:*": [
    SCOPE_COMMS_MESSAGE_READ,
    SCOPE_COMMS_MESSAGE_SEND,
    SCOPE_COMMS_EMAIL_READ,
    SCOPE_COMMS_EMAIL_SEND,
    SCOPE_COMMS_CALENDAR_READ,
    SCOPE_COMMS_CALENDAR_WRITE,
  ],
  "transact:*": [SCOPE_TRANSACT_PURCHASE, SCOPE_TRANSACT_SELL],
  "payments:*": [SCOPE_PAYMENTS_SEND, SCOPE_PAYMENTS_RECEIVE],
  "data:*": [SCOPE_DATA_READ, SCOPE_DATA_SHARE],
  "execute:*": [SCOPE_EXECUTE_TOOL],
  "generate:*": [SCOPE_GENERATE_CONTENT],
  "physical:*": [SCOPE_PHYSICAL_ENTER, SCOPE_PHYSICAL_EXIT],
  "robot:*": [SCOPE_ROBOT_OPERATE, SCOPE_ROBOT_MOVE, SCOPE_ROBOT_INTERACT],
  "drone:*": [SCOPE_DRONE_DELIVER, SCOPE_DRONE_CAPTURE],
  "vehicle:*": [SCOPE_VEHICLE_TRANSPORT, SCOPE_VEHICLE_CHARGE],
  "infrastructure:*": [SCOPE_INFRASTRUCTURE_MONITOR],
  // actuate:* — every member is sensitive; NO wildcard expansion.
};

function isCustomScope(s: string): boolean {
  return s.startsWith(CUSTOM_SCOPE_PREFIX) && s.length > CUSTOM_SCOPE_PREFIX.length;
}

/** Returns an error message if any scope is invalid; null if all valid.
 *  Custom scopes (prefix "custom:") are accepted as valid extensions. */
export function validateScopes(scopes: string[]): string | null {
  for (const s of scopes) {
    if (VALID_SCOPES.has(s)) continue;
    if (s in SCOPE_WILDCARDS) continue;
    if (isCustomScope(s)) continue;
    return `unknown scope "${s}": not in canonical vocabulary and not a custom: extension`;
  }
  return null;
}

/** Returns true if the scope is flagged as sensitive. Custom scopes are
 *  non-sensitive by default; applications may enforce policy out-of-band. */
export function isSensitive(scope: string): boolean {
  return SENSITIVE_SCOPES.has(scope);
}

/**
 * Replaces any wildcard scopes with their constituent non-sensitive scopes.
 * Deduplicates. Returns results in lexicographic order so callers see
 * deterministic output. Custom scopes pass through unchanged.
 */
export function expandScopes(scopes: string[]): string[] {
  const seen = new Set<string>();
  for (const s of scopes) {
    const children = SCOPE_WILDCARDS[s];
    if (children) {
      for (const c of children) seen.add(c);
    } else {
      seen.add(s);
    }
  }
  return [...seen].sort();
}

/** True if the required scope is present after wildcard expansion of `granted`. */
export function hasScope(granted: string[], required: string): boolean {
  return expandScopes(granted).includes(required);
}

/** Set of scopes in every input list after wildcard expansion. Lex-sorted. */
export function intersectScopes(...lists: string[][]): string[] {
  if (lists.length === 0) return [];
  let effective = new Set(expandScopes(lists[0]!));
  for (let i = 1; i < lists.length; i++) {
    const next = new Set(expandScopes(lists[i]!));
    const keep = new Set<string>();
    for (const s of effective) {
      if (next.has(s)) keep.add(s);
    }
    effective = keep;
  }
  return [...effective].sort();
}
