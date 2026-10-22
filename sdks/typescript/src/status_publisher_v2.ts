// Minimal signed-status publisher (SPEC-v2 §5.4 status publisher duties; Go
// status_publisher_v2.go).
//
// V2StatusPublisher signs status for one issuer under a separate status key:
// a genesis full list, same-sequence heartbeats that refresh freshness, and
// revocations as a push plus the cumulative full list at the next sequence.
// Each operation is a pure transition of V2StatusPublisherState; the caller
// MUST durably persist the returned state before publishing the returned
// objects, so a crash can never sign two different bodies at one sequence.

import { V2_MAX_STATUS_LIFETIME_SECONDS, checkedAddV2, validV2Timestamp } from "./clock_bounds_v2.js";
import { classifiedAsync, v2Classify, v2Errorf, wrapError } from "./errors_v2.js";
import { compareStrings, isWellFormedString, utf8Len } from "./json_v2.js";
import { MAX_REVOCATION_LIST_REFS_V2, MAX_REVOCATION_PUSH_REFS_V2 } from "./limits_v2.js";
import {
  cloneHybridPublicKey,
  placeholderV2Signature,
  signRevocationListV2WithSigner,
  signRevocationPushV2WithSigner,
  type RevocationListV2,
  type RevocationPushV2,
} from "./protocol_v2_wire.js";
import { keyRoleBindingV2, loadAnchoredSecurityJournalV2, type SecurityJournalStoreV2, type StatusKeyBindingV2 } from "./security_journal_v2.js";
import { signerPublicKeyV2, type SignerV2 } from "./signer_v2.js";
import { MAX_IDENTIFIER_LENGTH_BYTES, type HybridPublicKey } from "./types.js";

/** The publisher's durable state. */
export interface V2StatusPublisherState {
  issuerID: string;
  statusKeyID: string;
  /** The last signed sequence. */
  sequence: number;
  /** updated_at of the last signed full list. */
  updatedAt: number;
  /** The cumulative revoked set, sorted. */
  revoked: string[];
}

/** One transition's output; push is null except for a revocation. */
export interface V2StatusPublication {
  state: V2StatusPublisherState;
  list: RevocationListV2;
  push: RevocationPushV2 | null;
}

const isSortedUnique = (values: readonly string[]) => values.every((v, i) => i === 0 || compareStrings(values[i - 1]!, v) < 0);

/** Signs status for one issuer under one status key. */
export class V2StatusPublisher {
  readonly #issuerID: string;
  readonly #statusKey: HybridPublicKey;
  readonly #statusKeyID: string;
  readonly #signer: SignerV2;
  readonly #lifetime: number;

  private constructor(issuerID: string, statusKey: HybridPublicKey, statusKeyID: string, signer: SignerV2, lifetime: number) {
    this.#issuerID = issuerID;
    this.#statusKey = statusKey;
    this.#statusKeyID = statusKeyID;
    this.#signer = signer;
    this.#lifetime = lifetime;
  }

  /**
   * Binds an issuer's complete key to a separate status signer using the
   * deployment's authenticated role configuration: the anchored journal in
   * roles. Refuses (configuration_invalid), before any signature exists,
   * when roles is absent or not anchored; when the issuer key is not recorded
   * under a non-status role; when the status key's ID or either component
   * equals the ID or a component of any recorded non-status key; or when the
   * status key is not the issuer's highest-epoch configured status key.
   * lifetimeSeconds (1..86400) sets next_update - updated_at.
   */
  static async create(roles: SecurityJournalStoreV2 | null | undefined, issuerKey: HybridPublicKey, statusSigner: SignerV2 | null | undefined, lifetimeSeconds: number, signal?: AbortSignal): Promise<V2StatusPublisher> {
    return classifiedAsync("configuration_invalid", async () => {
      if (!Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1 || lifetimeSeconds > V2_MAX_STATUS_LIFETIME_SECONDS) {
        throw v2Errorf("configuration_invalid", `v2 status list lifetime must be 1..${V2_MAX_STATUS_LIFETIME_SECONDS} seconds`);
      }
      if (!roles) throw v2Errorf("configuration_invalid", "v2 status publisher requires the authenticated role configuration");
      let issuerBinding;
      try {
        issuerBinding = keyRoleBindingV2("issuer", issuerKey);
      } catch (err) {
        throw v2Classify("configuration_invalid", wrapError("v2 status publisher issuer key", err));
      }
      if (!statusSigner) throw v2Errorf("configuration_invalid", "v2 status publisher requires a status signer");
      let statusKey: HybridPublicKey;
      let statusBinding;
      try {
        statusKey = await signerPublicKeyV2(statusSigner);
        statusBinding = keyRoleBindingV2("status", statusKey);
      } catch (err) {
        throw v2Classify("configuration_invalid", err);
      }
      let journal;
      try {
        journal = await loadAnchoredSecurityJournalV2(roles, signal);
      } catch (err) {
        throw v2Classify("configuration_invalid", wrapError("v2 status publisher role configuration", err));
      }
      let issuerKnown = false;
      for (const b of journal.keyRoleHistory) {
        if (b.role === "status") continue;
        if (b.keyID === issuerBinding.keyID && b.ed25519Digest === issuerBinding.ed25519Digest && b.mlDsa65Digest === issuerBinding.mlDsa65Digest) {
          issuerKnown = true;
        }
        if (b.keyID === statusBinding.keyID || b.ed25519Digest === statusBinding.ed25519Digest || b.mlDsa65Digest === statusBinding.mlDsa65Digest ||
            b.ed25519Digest === statusBinding.mlDsa65Digest || b.mlDsa65Digest === statusBinding.ed25519Digest) {
          throw v2Errorf("configuration_invalid", `v2 status key reuses the key or a component of recorded ${b.role} key ${b.keyID}; status keys must be role-separated`);
        }
      }
      if (!issuerKnown) throw v2Errorf("configuration_invalid", "v2 status publisher issuer key is not recorded under a non-status role");
      let current: StatusKeyBindingV2 | null = null;
      for (const b of journal.statusKeyHistory) {
        if (b.issuerID === issuerBinding.keyID && b.epoch > (current?.epoch ?? 0)) current = b;
      }
      if (current === null || current.statusKeyID !== statusBinding.keyID || current.ed25519Digest !== statusBinding.ed25519Digest ||
          current.mlDsa65Digest !== statusBinding.mlDsa65Digest) {
        throw v2Errorf("configuration_invalid", "v2 status signer is not the issuer's current configured status key");
      }
      return new V2StatusPublisher(issuerBinding.keyID, cloneHybridPublicKey(statusKey), statusBinding.keyID, statusSigner, lifetimeSeconds);
    });
  }

  /** The issuer ID a verifier configures. */
  issuerID(): string {
    return this.#issuerID;
  }

  /** A copy of the complete status public key. */
  statusKey(): HybridPublicKey {
    return cloneHybridPublicKey(this.#statusKey);
  }

  /** Signs the first full list: sequence 1, an empty revoked set. */
  async genesis(updatedAt: number, signal?: AbortSignal): Promise<V2StatusPublication> {
    return classifiedAsync("configuration_invalid", async () => {
      return this.#list({ issuerID: this.#issuerID, statusKeyID: this.#statusKeyID, sequence: 0, updatedAt: 0, revoked: [] }, 1, updatedAt, signal);
    });
  }

  /** Re-signs the current sequence and set with a strictly later updated_at. */
  async heartbeat(state: V2StatusPublisherState, updatedAt: number, signal?: AbortSignal): Promise<V2StatusPublication> {
    return classifiedAsync("configuration_invalid", async () => {
      this.#checkState(state, updatedAt);
      return this.#list(state, state.sequence, updatedAt, signal);
    });
  }

  /**
   * Advances one sequence: a push of exactly the newly revoked IDs and the
   * cumulative full list at the same sequence, both timestamped at. Every ID
   * must be new, unique, and 1..512 bytes of UTF-8.
   */
  async revoke(state: V2StatusPublisherState, certIDs: readonly string[], at: number, signal?: AbortSignal): Promise<V2StatusPublication> {
    return classifiedAsync("configuration_invalid", async () => {
      this.#checkState(state, at);
      if (!Array.isArray(certIDs) || certIDs.length === 0 || certIDs.length > MAX_REVOCATION_PUSH_REFS_V2) {
        throw new Error(`v2 status revocation must name 1..${MAX_REVOCATION_PUSH_REFS_V2} certificate IDs`);
      }
      const added = [...certIDs].sort(compareStrings);
      const existing = new Set(state.revoked);
      added.forEach((id, i) => {
        if (typeof id !== "string" || id === "" || utf8Len(id) > MAX_IDENTIFIER_LENGTH_BYTES || !isWellFormedString(id) || (i > 0 && added[i - 1] === id)) {
          throw new Error(`v2 status revocation IDs must be unique UTF-8 of 1..${MAX_IDENTIFIER_LENGTH_BYTES} bytes`);
        }
        if (existing.has(id)) throw new Error(`v2 certificate "${id}" is already revoked; revocation is monotonic`);
      });
      if (state.revoked.length + added.length > MAX_REVOCATION_LIST_REFS_V2) {
        throw new Error(`v2 status list would exceed ${MAX_REVOCATION_LIST_REFS_V2} revoked references`);
      }
      const sequence = state.sequence + 1;
      if (sequence > Number.MAX_SAFE_INTEGER) throw new Error("v2 status sequence is exhausted");
      const push = await signRevocationPushV2WithSigner({
        version: 2, issuer_id: this.#issuerID, sequence, pushed_at: at, revoked: added.map((cert_id) => ({ cert_id })),
        signature: placeholderV2Signature(),
      }, this.#issuerID, this.#statusKey, this.#signer, { signal });
      const next: V2StatusPublisherState = { ...state, revoked: [...state.revoked, ...added].sort(compareStrings) };
      const out = await this.#list(next, sequence, at, signal);
      out.push = push;
      return out;
    });
  }

  #checkState(state: V2StatusPublisherState, at: number): void {
    if (!state || state.issuerID !== this.#issuerID || state.statusKeyID !== this.#statusKeyID || !Number.isSafeInteger(state.sequence) ||
        state.sequence < 1 || !validV2Timestamp(state.updatedAt) || !Array.isArray(state.revoked) || !isSortedUnique(state.revoked)) {
      throw v2Errorf("configuration_invalid", "v2 status publisher state does not belong to this issuer and status key, or its revoked set is not sorted and unique");
    }
    if (!(at > state.updatedAt)) throw new Error(`v2 status update time ${at} must be later than the last list's updated_at ${state.updatedAt}`);
  }

  async #list(state: V2StatusPublisherState, sequence: number, updatedAt: number, signal?: AbortSignal): Promise<V2StatusPublication> {
    const nextUpdate = checkedAddV2(updatedAt, this.#lifetime);
    if (!validV2Timestamp(updatedAt) || nextUpdate === null || !validV2Timestamp(nextUpdate)) {
      throw new Error("v2 status list times leave the timestamp domain");
    }
    const list = await signRevocationListV2WithSigner({
      version: 2, issuer_id: this.#issuerID, updated_at: updatedAt, next_update: nextUpdate, sequence,
      revoked: state.revoked.map((cert_id) => ({ cert_id })), signature: placeholderV2Signature(),
    }, this.#issuerID, this.#statusKey, this.#signer, { signal });
    return { state: { ...state, sequence, updatedAt, revoked: [...state.revoked] }, list, push: null };
  }
}

/** Go NewV2StatusPublisher. */
export function newV2StatusPublisher(roles: SecurityJournalStoreV2 | null | undefined, issuerKey: HybridPublicKey, statusSigner: SignerV2 | null | undefined, lifetimeSeconds: number, signal?: AbortSignal): Promise<V2StatusPublisher> {
  return V2StatusPublisher.create(roles, issuerKey, statusSigner, lifetimeSeconds, signal);
}
