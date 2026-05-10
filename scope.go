package ratify

import (
	"fmt"
	"slices"
	"strings"
)

// Canonical scope constants. Use these instead of bare strings.
// Format: domain:resource:action (colon-separated hierarchy)
const (
	// --- Meeting scopes ---
	ScopeMeetingAttend      = "meeting:attend"
	ScopeMeetingSpeak       = "meeting:speak"
	ScopeMeetingVideo       = "meeting:video"
	ScopeMeetingChat        = "meeting:chat"
	ScopeMeetingShareScreen = "meeting:share_screen"
	ScopeMeetingRecord      = "meeting:record" // sensitive

	// --- Communication scopes ---
	ScopeCommsMessageRead   = "comms:message:read"
	ScopeCommsMessageSend   = "comms:message:send"
	ScopeCommsMessageDelete = "comms:message:delete" // sensitive
	ScopeCommsEmailRead     = "comms:email:read"
	ScopeCommsEmailSend     = "comms:email:send"
	ScopeCommsEmailDelete   = "comms:email:delete" // sensitive
	ScopeCommsCalendarRead  = "comms:calendar:read"
	ScopeCommsCalendarWrite = "comms:calendar:write"

	// --- File scopes ---
	ScopeFilesRead  = "files:read"
	ScopeFilesWrite = "files:write" // sensitive

	// --- Identity scopes ---
	ScopeIdentityProve    = "identity:prove"
	ScopeIdentityDelegate = "identity:delegate" // sensitive

	// --- Presence scopes (candidate v1.x — not yet in canonical vocabulary) ---
	// ScopePresenceRepresent is proposed but NOT YET ADDED to validScopes or
	// sensitiveScopes. See docs/ROADMAP.md §"Candidate v1.x additions" for the
	// full design rationale and open questions before this ships.
	//
	// Intended semantics: the agent is authorized to attend and interact as a
	// direct representative of the principal. Distinct from generate:deepfake
	// (content generation) and identity:delegate (key delegation). Covers both
	// non-likeness representatives and full likeness agents (Tavus, HeyGen, etc.).
	// Sensitive — requires explicit human confirmation.
	//
	// Until this ships, platforms needing representation semantics should use the
	// custom: extension pattern: "custom:presence:represent"
	// ScopePresenceRepresent = "presence:represent" // proposed, sensitive

	// --- Transaction scopes (v1, core to the "transaction horizon" thesis) ---
	// ScopeTransactPurchase: buy goods/services on behalf of the principal
	ScopeTransactPurchase = "transact:purchase"
	// ScopeTransactSell: sell goods/services on behalf of the principal
	ScopeTransactSell = "transact:sell"
	// ScopePaymentsSend: initiate an outbound payment
	ScopePaymentsSend = "payments:send"
	// ScopePaymentsReceive: receive / collect a payment on behalf
	ScopePaymentsReceive = "payments:receive"
	// ScopePaymentsAuthorize: (sensitive) authorize movement of funds from an
	// account beyond standard purchase limits. Requires explicit grant.
	ScopePaymentsAuthorize = "payments:authorize"

	// --- Contract scopes ---
	ScopeContractRead = "contract:read"
	// ScopeContractSign: (sensitive) enter into a binding agreement
	ScopeContractSign = "contract:sign"

	// --- Data scopes (for structured application data, distinct from files) ---
	ScopeDataRead = "data:read"
	// ScopeDataWrite: (sensitive) create or modify data records
	ScopeDataWrite = "data:write"
	// ScopeDataDelete: (sensitive) delete data records
	ScopeDataDelete = "data:delete"
	// ScopeDataExport: (sensitive) bulk export — data exfiltration concern
	ScopeDataExport = "data:export"
	// ScopeDataShare: share data with an authorized third party
	ScopeDataShare = "data:share"

	// --- Execute scopes ---
	// ScopeExecuteTool: invoke an external tool / API on the principal's behalf
	// (covers MCP-style tool calls).
	ScopeExecuteTool = "execute:tool"
	// ScopeExecuteCode: (sensitive) execute arbitrary code on the principal's
	// compute resources. Requires explicit grant.
	ScopeExecuteCode = "execute:code"

	// --- Generate scopes (AI content generation on someone's behalf) ---
	// ScopeGenerateContent: generate text / image / audio / video content.
	ScopeGenerateContent = "generate:content"
	// ScopeGenerateDeepfake: (sensitive) generate content specifically intended
	// to imitate a specific real person. Sensitive by policy so that any
	// such generation creates an auditable explicit authorization trail.
	ScopeGenerateDeepfake = "generate:deepfake"

	// --- Physical-world scopes (v1, first-class coverage for embodied agents) ---
	// The entire Ratify design is channel-agnostic: the same cert/bundle/verify
	// semantics that authorize a software agent also authorize a robot, drone,
	// vehicle, or infrastructure controller. The scopes below are the canonical
	// vocabulary for agents that take action in physical space. Location,
	// temporal, and magnitude bounds are expressed as first-class constraints
	// on the DelegationCert (see types.go Constraint); the scopes below state
	// *what* the agent may do, constraints state *where/when/how much*.

	// ScopePhysicalEnter: enter a physical zone (non-sensitive — the real
	// gate is typically the geo_polygon/geo_circle constraint on the cert).
	ScopePhysicalEnter = "physical:enter"
	// ScopePhysicalExit: exit a physical zone.
	ScopePhysicalExit = "physical:exit"
	// ScopePhysicalActuate: (sensitive) activate a physical actuator — valve,
	// lock, door, latch. Anything that moves matter in the world.
	ScopePhysicalActuate = "physical:actuate"
	// ScopePhysicalManipulate: (sensitive) manipulate physical objects
	// (pick-and-place, lift, rotate). Distinct from actuate: manipulation
	// targets objects, actuation targets fixtures.
	ScopePhysicalManipulate = "physical:manipulate"

	// ScopeRobotOperate: operate a robotic platform (power on, hold, idle
	// motion). The umbrella permission for embodied robots; per-action
	// restrictions use scope chain intersection + constraints.
	ScopeRobotOperate = "robot:operate"
	// ScopeRobotMove: autonomous locomotion — the robot may move in space.
	// Pair with a geo_polygon/geo_circle constraint to bound where.
	ScopeRobotMove = "robot:move"
	// ScopeRobotInteract: the robot may interact with humans or objects in
	// its environment (touch, grasp, gesture). Non-sensitive at the scope
	// level; applications requiring higher assurance combine this with
	// explicit physical:manipulate for stronger semantics.
	ScopeRobotInteract = "robot:interact"

	// ScopeDroneFly: (sensitive) operate a drone under active flight.
	// Nearly always paired with geo + altitude + time_window constraints.
	ScopeDroneFly = "drone:fly"
	// ScopeDroneDeliver: conduct a delivery mission.
	ScopeDroneDeliver = "drone:deliver"
	// ScopeDroneCapture: capture imagery / telemetry data during a flight.
	ScopeDroneCapture = "drone:capture"

	// ScopeVehicleOperate: (sensitive) operate a vehicle — cars, trucks,
	// watercraft, aircraft other than drones. Max-speed and geo constraints
	// are strongly recommended.
	ScopeVehicleOperate = "vehicle:operate"
	// ScopeVehicleTransport: transport a named passenger or payload.
	ScopeVehicleTransport = "vehicle:transport"
	// ScopeVehicleCharge: access charging infrastructure / refueling.
	ScopeVehicleCharge = "vehicle:charge"

	// ScopeInfrastructureMonitor: read sensor values and system state from
	// a piece of infrastructure (HVAC, power, access logs). Read-only.
	ScopeInfrastructureMonitor = "infrastructure:monitor"
	// ScopeInfrastructureControl: (sensitive) modify infrastructure state —
	// HVAC setpoints, breaker state, door policy, etc.
	ScopeInfrastructureControl = "infrastructure:control"
	// ScopeInfrastructureAccess: (sensitive) unlock / grant entry to a
	// restricted facility. Pair with geo + time_window constraints.
	ScopeInfrastructureAccess = "infrastructure:access"

	// ScopeActuateValve: (sensitive) generic valve operation.
	ScopeActuateValve = "actuate:valve"
	// ScopeActuateMotor: (sensitive) generic motor / actuator operation.
	ScopeActuateMotor = "actuate:motor"
	// ScopeActuateSwitch: (sensitive) generic switch / relay operation.
	ScopeActuateSwitch = "actuate:switch"
)

// CustomScopePrefix is the extension-pattern prefix for application-specific
// scopes that are not in the canonical vocabulary. Any scope string starting
// with this prefix is accepted by ValidateScopes, passed through ExpandScopes
// unchanged, and treated as non-sensitive unless the application opts in via
// out-of-band policy.
//
// Example: "custom:acme:inventory:read" — Acme Corp's custom scope for their
// inventory system.
const CustomScopePrefix = "custom:"

// sensitiveScopes require explicit human confirmation beyond standard delegation.
// These are NEVER introduced by wildcard expansion.
var sensitiveScopes = map[string]bool{
	ScopeMeetingRecord:         true,
	ScopeCommsMessageDelete:    true,
	ScopeCommsEmailDelete:      true,
	ScopeFilesWrite:            true,
	ScopeIdentityDelegate:      true,
	ScopePaymentsAuthorize:     true,
	ScopeContractSign:          true,
	ScopeDataWrite:             true,
	ScopeDataDelete:            true,
	ScopeDataExport:            true,
	ScopeExecuteCode:           true,
	ScopeGenerateDeepfake:      true,
	ScopePhysicalActuate:       true,
	ScopePhysicalManipulate:    true,
	ScopeDroneFly:              true,
	ScopeVehicleOperate:        true,
	ScopeInfrastructureControl: true,
	ScopeInfrastructureAccess:  true,
	ScopeActuateValve:          true,
	ScopeActuateMotor:          true,
	ScopeActuateSwitch:         true,
}

// validScopes is the complete canonical vocabulary for v1.
var validScopes = map[string]bool{
	ScopeMeetingAttend:         true,
	ScopeMeetingSpeak:          true,
	ScopeMeetingVideo:          true,
	ScopeMeetingChat:           true,
	ScopeMeetingShareScreen:    true,
	ScopeMeetingRecord:         true,
	ScopeCommsMessageRead:      true,
	ScopeCommsMessageSend:      true,
	ScopeCommsMessageDelete:    true,
	ScopeCommsEmailRead:        true,
	ScopeCommsEmailSend:        true,
	ScopeCommsEmailDelete:      true,
	ScopeCommsCalendarRead:     true,
	ScopeCommsCalendarWrite:    true,
	ScopeFilesRead:             true,
	ScopeFilesWrite:            true,
	ScopeIdentityProve:         true,
	ScopeIdentityDelegate:      true,
	ScopeTransactPurchase:      true,
	ScopeTransactSell:          true,
	ScopePaymentsSend:          true,
	ScopePaymentsReceive:       true,
	ScopePaymentsAuthorize:     true,
	ScopeContractRead:          true,
	ScopeContractSign:          true,
	ScopeDataRead:              true,
	ScopeDataWrite:             true,
	ScopeDataDelete:            true,
	ScopeDataExport:            true,
	ScopeDataShare:             true,
	ScopeExecuteTool:           true,
	ScopeExecuteCode:           true,
	ScopeGenerateContent:       true,
	ScopeGenerateDeepfake:      true,
	ScopePhysicalEnter:         true,
	ScopePhysicalExit:          true,
	ScopePhysicalActuate:       true,
	ScopePhysicalManipulate:    true,
	ScopeRobotOperate:          true,
	ScopeRobotMove:             true,
	ScopeRobotInteract:         true,
	ScopeDroneFly:              true,
	ScopeDroneDeliver:          true,
	ScopeDroneCapture:          true,
	ScopeVehicleOperate:        true,
	ScopeVehicleTransport:      true,
	ScopeVehicleCharge:         true,
	ScopeInfrastructureMonitor: true,
	ScopeInfrastructureControl: true,
	ScopeInfrastructureAccess:  true,
	ScopeActuateValve:          true,
	ScopeActuateMotor:          true,
	ScopeActuateSwitch:         true,
}

// scopeWildcards maps wildcard shorthand to constituent non-sensitive scopes.
// Sensitive scopes are NEVER included in wildcards — they must be granted explicitly.
var scopeWildcards = map[string][]string{
	"meeting:*": {
		ScopeMeetingAttend, ScopeMeetingSpeak, ScopeMeetingVideo,
		ScopeMeetingChat, ScopeMeetingShareScreen,
		// meeting:record excluded (sensitive)
	},
	"comms:message:*": {ScopeCommsMessageRead, ScopeCommsMessageSend},
	"comms:email:*":   {ScopeCommsEmailRead, ScopeCommsEmailSend},
	"comms:*": {
		ScopeCommsMessageRead, ScopeCommsMessageSend,
		ScopeCommsEmailRead, ScopeCommsEmailSend,
		ScopeCommsCalendarRead, ScopeCommsCalendarWrite,
	},
	"transact:*": {ScopeTransactPurchase, ScopeTransactSell},
	"payments:*": {ScopePaymentsSend, ScopePaymentsReceive},
	// data:* excludes write/delete/export (all sensitive)
	"data:*": {ScopeDataRead, ScopeDataShare},
	// execute:* excludes code (sensitive)
	"execute:*": {ScopeExecuteTool},
	// generate:* excludes deepfake (sensitive)
	"generate:*": {ScopeGenerateContent},
	// physical:* excludes actuate/manipulate (both sensitive)
	"physical:*": {ScopePhysicalEnter, ScopePhysicalExit},
	// robot:* — none individually sensitive, but high-stakes robot actions
	// should compose with physical:manipulate for explicit consent.
	"robot:*": {ScopeRobotOperate, ScopeRobotMove, ScopeRobotInteract},
	// drone:* excludes fly (sensitive)
	"drone:*": {ScopeDroneDeliver, ScopeDroneCapture},
	// vehicle:* excludes operate (sensitive)
	"vehicle:*": {ScopeVehicleTransport, ScopeVehicleCharge},
	// infrastructure:* excludes control/access (both sensitive)
	"infrastructure:*": {ScopeInfrastructureMonitor},
	// actuate:* — every member is sensitive, so NO wildcard expansion.
	// Every actuate grant must be explicit.
}

// ValidateScopes returns an error if any scope is not in the canonical
// vocabulary, and is not a wildcard, and does not start with CustomScopePrefix.
//
// Custom scopes are allowed for application-specific extensions. See the
// protocol spec §9.4 for the extension rules.
func ValidateScopes(scopes []string) error {
	for _, s := range scopes {
		if isValidScope(s) {
			continue
		}
		return fmt.Errorf("unknown scope %q: not in canonical vocabulary and not a custom: extension", s)
	}
	return nil
}

// isValidScope returns true iff s is canonical, a wildcard, or a custom extension.
func isValidScope(s string) bool {
	if validScopes[s] {
		return true
	}
	if scopeWildcards[s] != nil {
		return true
	}
	if strings.HasPrefix(s, CustomScopePrefix) && len(s) > len(CustomScopePrefix) {
		return true
	}
	return false
}

// ExpandScopes replaces any wildcard scopes with their constituent scopes.
// Deduplicates the result and returns scopes in lexicographic order so that
// callers (and downstream serializers) see deterministic output.
//
// Custom scopes (prefix "custom:") pass through unchanged — they are never
// expanded by wildcards.
func ExpandScopes(scopes []string) []string {
	seen := make(map[string]bool)
	for _, s := range scopes {
		if children, ok := scopeWildcards[s]; ok {
			for _, c := range children {
				seen[c] = true
			}
		} else {
			seen[s] = true
		}
	}
	result := make([]string, 0, len(seen))
	for s := range seen {
		result = append(result, s)
	}
	slices.Sort(result)
	return result
}

// HasScope checks if the granted scope list covers the required scope,
// including wildcard expansion.
func HasScope(granted []string, required string) bool {
	return slices.Contains(ExpandScopes(granted), required)
}

// IntersectScopes returns the set of scopes present in every input list,
// after wildcard expansion. This is the effective grant of a delegation
// chain: an agent can only exercise scopes that every cert in the chain
// conveyed.
//
// Sensitive scopes are never introduced by wildcard expansion, so a
// sensitive scope not present explicitly in every list is filtered out.
// Custom scopes pass through the intersection normally.
//
// Returns nil for an empty input. For a single list, returns its expansion.
func IntersectScopes(lists ...[]string) []string {
	if len(lists) == 0 {
		return nil
	}
	effective := make(map[string]bool)
	for _, s := range ExpandScopes(lists[0]) {
		effective[s] = true
	}
	for i := 1; i < len(lists); i++ {
		next := make(map[string]bool)
		for _, s := range ExpandScopes(lists[i]) {
			next[s] = true
		}
		for s := range effective {
			if !next[s] {
				delete(effective, s)
			}
		}
	}
	result := make([]string, 0, len(effective))
	for s := range effective {
		result = append(result, s)
	}
	slices.Sort(result)
	return result
}

// IsSensitive returns true if the scope requires explicit human confirmation.
// Custom scopes (prefix "custom:") are NOT sensitive by default; applications
// that want sensitive custom scopes should enforce that at the application
// policy layer.
func IsSensitive(scope string) bool {
	return sensitiveScopes[scope]
}
