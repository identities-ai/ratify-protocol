// Dual-root composition profile ledger (SPEC-v2 §7.14; Go
// v2reference/approval_ledger.go). TEST ONLY.
//
// An approval set names one action through its authenticated fields. The
// ledger derives the expected session context with invocation_id =
// approval_set_id and never accepts a caller-supplied context. It marks the
// action executable only when both released allows match the set and are
// still within their deadlines, executes it at most once, and never counts
// one released decision toward two sets. The composite result is
// application state, not a Protocol receipt.

import type { V2AuthoritativeClock } from "../claim_store_v2.js";
import { keyIDV2 } from "../crypto_v2.js";
import { V2SentinelError } from "../errors_v2.js";
import { bytesEqual } from "../json_v2.js";
import { buildSessionContextV2 } from "../operation_context_v2.js";
import { bundleHashV2, decodeProofBundleV2, equalHybridPublicKeys } from "../protocol_v2_wire.js";
import type { V2ReleasedDecision } from "../release_v2.js";
import { validateRequiredScopeV2 } from "../scope_v2.js";
import type { HybridPublicKey } from "../types.js";
import { MutexTestOnly } from "./store.js";

export const ErrApprovalNotReleasedTestOnly = new V2SentinelError("v2reference: approval is not a released allow");
export const ErrApprovalActionMismatchTestOnly = new V2SentinelError("v2reference: approval does not bind this approval set's action");
export const ErrApprovalRootMismatchTestOnly = new V2SentinelError("v2reference: approval chain does not end at the slot's pinned root");
export const ErrApprovalSlotFilledTestOnly = new V2SentinelError("v2reference: slot already holds a different approval");
export const ErrApprovalReusedTestOnly = new V2SentinelError("v2reference: approval is already recorded in another approval set");
export const ErrApprovalIncompleteTestOnly = new V2SentinelError("v2reference: approval set is missing a released approval");
export const ErrApprovalExpiredTestOnly = new V2SentinelError("v2reference: an approval is past its release deadline");
export const ErrApprovalAlreadyExecutedTestOnly = new V2SentinelError("v2reference: approval set already executed");
export const ErrApprovalSetInvalidTestOnly = new V2SentinelError("v2reference: invalid approval set");
export const ErrApprovalSetUnknownTestOnly = new V2SentinelError("v2reference: unknown approval set");
export const ErrApprovalSetAlreadyExistsTestOnly = new V2SentinelError("v2reference: approval set already open");

/** The authenticated approval set opened before either challenge is issued. */
export interface ApprovalSetTestOnly {
  approvalSetID: string;
  verifierID: string;
  workspaceID: string;
  sessionID: string;
  agentPublicKey: HybridPublicKey;
  requiredScope: string;
  /** The action's 32-byte operation-context hash. */
  requestHash: Uint8Array;
  /** The complete public keys of the two pinned roots, in slot order. */
  roots: [HybridPublicKey, HybridPublicKey];
}

interface ApprovalState {
  set: ApprovalSetTestOnly;
  agentID: string;
  rootIDs: [string, string];
  sessionContext: Uint8Array;
  approvals: [{ claimID: string; decision: V2ReleasedDecision } | null, { claimID: string; decision: V2ReleasedDecision } | null];
  executed: boolean;
}

/** Every operation is one atomic step under a mutex. */
export class ApprovalLedgerTestOnly {
  readonly mutex = new MutexTestOnly();
  sets = new Map<string, ApprovalState>();
  /** Recorded claim ID -> the one approval set it counts toward. */
  recorded = new Map<string, string>();

  /** Records an approval set; derives the agent and root IDs and the expected context. */
  async open(set: ApprovalSetTestOnly): Promise<void> {
    if (!set.approvalSetID || set.requestHash?.length !== 32 || validateRequiredScopeV2(set.requiredScope) !== null) throw ErrApprovalSetInvalidTestOnly;
    let agentID: string;
    let rootIDs: [string, string];
    let sessionContext: Uint8Array;
    try {
      agentID = keyIDV2(set.agentPublicKey);
      rootIDs = [keyIDV2(set.roots[0]), keyIDV2(set.roots[1])];
      sessionContext = buildSessionContextV2({
        verifier_id: set.verifierID, workspace_id: set.workspaceID, agent_id: agentID, session_id: set.sessionID,
        invocation_id: set.approvalSetID, request_hash: set.requestHash,
      });
    } catch {
      throw ErrApprovalSetInvalidTestOnly;
    }
    if (rootIDs[0] === rootIDs[1]) throw ErrApprovalSetInvalidTestOnly;
    return this.mutex.run(() => {
      if (this.sets.has(set.approvalSetID)) throw ErrApprovalSetAlreadyExistsTestOnly;
      const copy: ApprovalSetTestOnly = {
        ...set, requestHash: Uint8Array.from(set.requestHash),
        agentPublicKey: { ed25519: Uint8Array.from(set.agentPublicKey.ed25519), ml_dsa_65: Uint8Array.from(set.agentPublicKey.ml_dsa_65) },
        roots: [
          { ed25519: Uint8Array.from(set.roots[0].ed25519), ml_dsa_65: Uint8Array.from(set.roots[0].ml_dsa_65) },
          { ed25519: Uint8Array.from(set.roots[1].ed25519), ml_dsa_65: Uint8Array.from(set.roots[1].ml_dsa_65) },
        ],
      };
      this.sets.set(set.approvalSetID, { set: copy, agentID, rootIDs, sessionContext, approvals: [null, null], executed: false });
    });
  }

  /**
   * Binds a released decision and the exact bundle it verified to slot 0 or
   * 1; returns whether both slots are now filled. Checks in SPEC-v2 §7.14
   * order: released allow; bundle hash; reuse; verifier, agent, scope and
   * derived session context; pinned root; slot.
   */
  async recordApproval(setID: string, slot: number, decision: V2ReleasedDecision | null, bundleWire: Uint8Array): Promise<boolean> {
    if (slot !== 0 && slot !== 1) throw new Error("v2reference: slot must be 0 or 1");
    if (!decision || decision.decision() !== "allow") throw ErrApprovalNotReleasedTestOnly;
    let receipt;
    try {
      receipt = decision.receipt();
    } catch {
      throw ErrApprovalNotReleasedTestOnly;
    }
    let bundle;
    let bundleHash = "";
    try {
      bundle = decodeProofBundleV2(bundleWire);
      bundleHash = bundleHashV2(bundle);
    } catch {
      throw ErrApprovalActionMismatchTestOnly;
    }
    if (bundleHash !== receipt.bundle_hash) throw ErrApprovalActionMismatchTestOnly;
    const claimID = decision.claimID();
    return this.mutex.run(() => {
      const state = this.sets.get(setID);
      if (!state) throw ErrApprovalSetUnknownTestOnly;
      const owner = this.recorded.get(claimID);
      if (owner !== undefined && owner !== setID) throw ErrApprovalReusedTestOnly;
      const set = state.set;
      if (receipt.verifier_id !== set.verifierID || bundle.verifier_id !== set.verifierID ||
          receipt.agent_id !== state.agentID || bundle.agent_id !== state.agentID || !equalHybridPublicKeys(bundle.agent_pub_key, set.agentPublicKey) ||
          receipt.required_scope !== set.requiredScope ||
          bundle.session_context === null || !bytesEqual(bundle.session_context, state.sessionContext)) {
        throw ErrApprovalActionMismatchTestOnly;
      }
      const chain = bundle.delegations ?? [];
      if (chain.length === 0) throw ErrApprovalRootMismatchTestOnly;
      const root = chain[chain.length - 1]!;
      if (root.issuer_id !== state.rootIDs[slot] || !equalHybridPublicKeys(root.issuer_pub_key, set.roots[slot]!) ||
          !(receipt.issuer_ids ?? []).includes(state.rootIDs[slot]!)) {
        throw ErrApprovalRootMismatchTestOnly;
      }
      const current = state.approvals[slot];
      if (current) {
        if (current.claimID !== claimID) throw ErrApprovalSlotFilledTestOnly;
      } else {
        state.approvals[slot] = { claimID, decision };
        this.recorded.set(claimID, setID);
      }
      return state.approvals[0] !== null && state.approvals[1] !== null;
    });
  }

  /** Atomically checks both approvals are still allowed now and marks the set executed once. */
  async execute(setID: string, clock: V2AuthoritativeClock): Promise<void> {
    return this.mutex.run(async () => {
      const state = this.sets.get(setID);
      if (!state) throw ErrApprovalSetUnknownTestOnly;
      if (state.executed) throw ErrApprovalAlreadyExecutedTestOnly;
      if (state.approvals[0] === null || state.approvals[1] === null) throw ErrApprovalIncompleteTestOnly;
      for (const approval of state.approvals) {
        if (!(await approval!.decision.allowed(clock))) throw ErrApprovalExpiredTestOnly;
      }
      state.executed = true;
    });
  }
}

/** Maps a ledger error to the vector's class names. */
export function ledgerErrorClassTestOnly(err: unknown): string {
  const classes: [string, Error][] = [
    ["approval_set_invalid", ErrApprovalSetInvalidTestOnly], ["not_released", ErrApprovalNotReleasedTestOnly],
    ["action_mismatch", ErrApprovalActionMismatchTestOnly], ["root_mismatch", ErrApprovalRootMismatchTestOnly],
    ["slot_filled", ErrApprovalSlotFilledTestOnly], ["approval_reused", ErrApprovalReusedTestOnly], ["incomplete", ErrApprovalIncompleteTestOnly],
    ["expired", ErrApprovalExpiredTestOnly], ["already_executed", ErrApprovalAlreadyExecutedTestOnly],
  ];
  for (const [name, target] of classes) if (err === target) return name;
  if (err !== null && err !== undefined) return `unexpected: ${(err as Error)?.message ?? String(err)}`;
  return "";
}
