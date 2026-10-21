// Shared Protocol v2 conformance corpus runner (TypeScript). Every file in
// testvectors/v2 is loaded; positive vectors must reproduce byte-for-byte and
// every negative must be rejected with the same language-neutral class as
// the Go reference (v2_conformance_test.go). An unknown corpus file fails.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256, sha384 } from "@noble/hashes/sha2";
import { shake256 } from "@noble/hashes/sha3";

import { hybridKeypairFromSeeds, deriveID } from "../src/crypto.js";
import { buildSessionContextV2, operationContextV2Hash } from "../src/operation_context_v2.js";
import { challengeClaimDigestV2, protocolClaimIDV2 } from "../src/challenge_claim_v2.js";
import {
  V2_OBJECT_TYPE,
  deriveKeyIDV2,
  signV2Statement,
  v2MLDSAContext,
  v2SigningMessage,
  type HybridKeyPairV2,
} from "../src/crypto_v2.js";
import { ErrV2ClaimProofConflict, ErrV2RateLimitExceeded, v2ErrorClassOf } from "../src/errors_v2.js";
import { base64Encode, canonicalJSONV2, gAny, hexOf, parseJSONV2, type JNode } from "../src/json_v2.js";
import {
  bundleHashV2,
  decodeDelegationCertV2,
  decodeProofBundleV2,
  decodeRevocationListV2,
  decodeRevocationPushV2,
  delegationCertV2SignBytes,
  encodeDelegationCertV2,
  encodeProofBundleV2,
  encodeRevocationListV2,
  encodeRevocationPushV2,
  statusEvidenceDigestV2,
  verifyDelegationCertV2Signature,
  verifyProofBundleV2Signatures,
  verifyRevocationListV2Signature,
  verifyRevocationPushV2Signature,
  type ProofBundleV2,
} from "../src/protocol_v2_wire.js";
import {
  acceptKeyRotationStatementV2,
  decodeKeyRotationStatementV2,
  encodeKeyRotationStatementV2,
  keyRotationStatementV2Digest,
  keyRotationStatementV2SignBytes,
  newKeyRotationV2Journal,
  recoverKeyRotationV2,
  signKeyRotationStatementV2,
  verifyKeyRotationStatementV2,
  type KeyRotationStatementV2,
  type KeyRotationV2Journal,
  type KeyRotationV2State,
  type V2AppendResult,
} from "../src/key_rotation_v2.js";
import { decodeWitnessEntryV2, encodeWitnessEntryV2, verifyWitnessEntryV2, witnessEntryV2Digest, type WitnessV2Head } from "../src/witness_v2.js";
import {
  checkVerificationReceiptV2BundleBinding,
  decodeVerificationReceiptV2,
  encodeVerificationReceiptV2,
  verificationReceiptV2Body,
  verificationReceiptV2Digest,
  verifyVerificationReceiptV2,
  type ReceiptV2Head,
  type StatusEvidenceEntryV2,
} from "../src/verification_receipt_v2.js";
import {
  decodeTransactionReceiptV2,
  transactionReceiptV2SignBytes,
  verifyTransactionReceiptV2Signatures,
} from "../src/transaction_receipt_v2.js";
import {
  applyRevocationListV2,
  applyRevocationPushV2,
  emptyRevocationStatusStateV2,
  revocationStatusForCertV2,
  transitionRevocationStatusEpochV2,
  type RevocationStatusPolicyV2,
  type RevocationStatusResultV2,
  type RevocationStatusStateV2,
} from "../src/status_state_v2.js";
import { newV2ContextPolicy } from "../src/context_policy_v2.js";
import {
  verifyProofBundleV2,
  type ClaimStoreV2,
  type ExpectedChallengeV2,
  type V2ChallengeClaim,
  type V2ClaimResult,
  type V2VerifyCallbacks,
  type V2VerifyRequest,
} from "../src/verify_v2.js";
import type { V2AudienceMembership, V2RateReservation } from "../src/audience_v2.js";
import type { HybridPublicKey } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTOR_DIR = join(__dirname, "..", "..", "..", "testvectors", "v2");

// Every corpus file must be handled here. A new file fails until a runner exists.
const HANDLED_FILES = new Set([
  "README.md", "derive-external-mu.py", "keys.json", "objects.json", "object-negatives.json", "verifier-ordering.json",
  "status-sequences.json", "log-sequences.json", "rotation-sequences.json", "key-rotation-signature.json",
  "delegation-signature.json", "operation-session-context.json", "challenge-claim.json",
]);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any;

const load = (name: string): Any => JSON.parse(readFileSync(join(VECTOR_DIR, name), "utf8"));
const unb64 = (s: string): Uint8Array => {
  const out = new Uint8Array(Buffer.from(s, "base64"));
  assert.equal(base64Encode(out), s, `non-canonical base64 in vector: ${s.slice(0, 20)}`);
  return out;
};
const hex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));
const pubOf = (o: { ed25519: string; ml_dsa_65: string }): HybridPublicKey => ({ ed25519: unb64(o.ed25519), ml_dsa_65: unb64(o.ml_dsa_65) });
const eqBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const utf8 = (b: Uint8Array) => new TextDecoder().decode(b);

// ---------------------------------------------------------------------------
// Keys

interface Fixture {
  pair: Map<string, HybridKeyPairV2>;
  id: Map<string, string>;
}

const keysFile = load("keys.json");
const fixturePromise: Promise<Fixture> = (async () => {
  const fx: Fixture = { pair: new Map(), id: new Map() };
  for (const k of keysFile.keys) {
    const { publicKey, privateKey } = await hybridKeypairFromSeeds(hex(k.ed25519_seed_hex), hex(k.ml_dsa_65_seed_hex));
    fx.pair.set(k.name, { publicKey, privateKey });
    fx.id.set(k.name, k.key_id_v2);
  }
  return fx;
})();
const pub = (fx: Fixture, name: string): HybridPublicKey => {
  const p = fx.pair.get(name);
  assert.ok(p, `unknown fixture key ${name}`);
  return p.publicKey;
};

const objectsFile = load("objects.json");
const objectByKind = (kind: string) => {
  const o = objectsFile.objects.find((x: Any) => x.kind === kind);
  assert.ok(o, `no ${kind} object`);
  return o;
};

function setTopLevelString(wire: Uint8Array, field: string, value: string): Uint8Array {
  const obj = gAny(parseJSONV2(wire)) as Record<string, unknown>;
  obj[field] = value;
  return canonicalJSONV2(obj);
}

function classOf(fn: () => unknown): string {
  try {
    fn();
    return "";
  } catch (err) {
    return v2ErrorClassOf(err);
  }
}

async function classOfAsync(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return "";
  } catch (err) {
    return v2ErrorClassOf(err);
  }
}

test("v2 corpus: every file in testvectors/v2 has a runner", () => {
  const files = readdirSync(VECTOR_DIR);
  const unknown = files.filter((f) => !HANDLED_FILES.has(f));
  assert.deepEqual(unknown, [], `unhandled corpus files: ${unknown.join(", ")}`);
  for (const f of HANDLED_FILES) assert.ok(files.includes(f), `expected corpus file ${f} is missing`);
});

test("v2 conformance: keys.json", async () => {
  const fx = await fixturePromise;
  assert.ok(keysFile.keys.length > 0);
  for (const k of keysFile.keys) {
    const p = fx.pair.get(k.name)!;
    assert.ok(eqBytes(p.publicKey.ed25519, unb64(k.public_key.ed25519)) && eqBytes(p.publicKey.ml_dsa_65, unb64(k.public_key.ml_dsa_65)),
      `${k.name}: seeds do not derive the pinned public key`);
    const independent = hexOf(sha256(new Uint8Array([...new TextEncoder().encode("ratify-key-id-v2\0"), ...p.publicKey.ed25519, ...p.publicKey.ml_dsa_65])));
    assert.equal(independent, k.key_id_v2, `${k.name}: independent key ID`);
    assert.equal(deriveKeyIDV2(pubOf(k.public_key)), k.key_id_v2, `${k.name}: key_id_v2`);
    const v1 = deriveID(pubOf(k.public_key));
    assert.equal(v1, k.v1_key_id_128, `${k.name}: v1 ID`);
    assert.notEqual(v1, k.key_id_v2.slice(0, 32), `${k.name}: v1 ID aliases the v2 prefix`);
  }
  const bundleWire = unb64(objectByKind("proof_bundle").wire_b64);
  const witnessWire = unb64(objectByKind("witness_entry").wire_b64);
  assert.ok(keysFile.invalid_v2_key_ids.length > 0);
  for (const bad of keysFile.invalid_v2_key_ids) {
    assert.equal(classOf(() => decodeProofBundleV2(setTopLevelString(bundleWire, "verifier_id", bad.value))), bad.expected_error_class, `${bad.name} as verifier_id`);
    assert.equal(classOf(() => decodeWitnessEntryV2(setTopLevelString(witnessWire, "witness_id", bad.value))), bad.expected_error_class, `${bad.name} as witness_id`);
  }
});

// ---------------------------------------------------------------------------
// Per-kind procedures (object-negatives.json procedure_by_kind)

function witnessHead(h: Any): WitnessV2Head {
  const accepted = new Map<number, Uint8Array>();
  for (const [seq, d] of Object.entries(h.accepted_digests_b64 ?? {})) accepted.set(Number(seq), unb64(d as string));
  return { logID: h.log_id, sequence: h.sequence, headHash: unb64(h.head_hash_b64), acceptedDigests: accepted, frozen: h.frozen };
}

const receiptHead = (h: Any): ReceiptV2Head => ({ ...witnessHead(h), verifierID: h.verifier_id });

function rotationState(s: Any, fx: Fixture): KeyRotationV2State {
  return {
    authorityID: s.authority_id, recoveryEpoch: s.recovery_epoch, role: s.role, sequence: s.sequence,
    headHash: unb64(s.head_hash_b64), currentKey: pub(fx, s.current_key), usedKeyIDs: [...s.used_key_ids],
  };
}

async function verifyObject(fx: Fixture, kind: string, wire: Uint8Array, bundleWire: Uint8Array | null, vc: Any): Promise<void> {
  switch (kind) {
    case "delegation_certificate":
      return verifyDelegationCertV2Signature(decodeDelegationCertV2(wire));
    case "proof_bundle":
      return verifyProofBundleV2Signatures(decodeProofBundleV2(wire));
    case "revocation_list":
      return verifyRevocationListV2Signature(decodeRevocationListV2(wire), vc.bound_issuer_id, pub(fx, vc.status_key));
    case "revocation_push":
      return verifyRevocationPushV2Signature(decodeRevocationPushV2(wire), vc.bound_issuer_id, pub(fx, vc.status_key));
    case "key_rotation_statement":
      return verifyKeyRotationStatementV2(decodeKeyRotationStatementV2(wire), rotationState(vc.rotation_state, fx), vc.now, vc.future_skew_seconds);
    case "witness_entry":
      await verifyWitnessEntryV2(decodeWitnessEntryV2(wire), witnessHead(vc.head), pub(fx, vc.witness_key));
      return;
    case "transaction_receipt":
      return verifyTransactionReceiptV2Signatures(await decodeTransactionReceiptV2(wire));
    case "verification_receipt":
      await verifyVerificationReceiptV2(decodeVerificationReceiptV2(wire), pub(fx, vc.verifier_key), receiptHead(vc.head));
      return;
    case "receipt_bundle_binding": {
      const r = decodeVerificationReceiptV2(wire);
      const b = decodeProofBundleV2(bundleWire!);
      return checkVerificationReceiptV2BundleBinding(r, b);
    }
  }
  assert.fail(`unknown kind ${kind}`);
}

async function reencode(kind: string, wire: Uint8Array): Promise<Uint8Array> {
  switch (kind) {
    case "delegation_certificate": return encodeDelegationCertV2(decodeDelegationCertV2(wire));
    case "proof_bundle": return encodeProofBundleV2(decodeProofBundleV2(wire));
    case "revocation_list": return encodeRevocationListV2(decodeRevocationListV2(wire));
    case "revocation_push": return encodeRevocationPushV2(decodeRevocationPushV2(wire));
    case "key_rotation_statement": return encodeKeyRotationStatementV2(decodeKeyRotationStatementV2(wire));
    case "witness_entry": return encodeWitnessEntryV2(decodeWitnessEntryV2(wire));
    case "transaction_receipt": {
      const { encodeTransactionReceiptV2 } = await import("../src/transaction_receipt_v2.js");
      return encodeTransactionReceiptV2(await decodeTransactionReceiptV2(wire));
    }
    case "verification_receipt": return encodeVerificationReceiptV2(decodeVerificationReceiptV2(wire));
  }
  assert.fail(`unknown kind ${kind}`);
}

async function projection(wire: Uint8Array, field: string): Promise<Uint8Array> {
  const root = parseJSONV2(wire);
  assert.equal(root.k, "obj");
  const drop = (n: JNode, ...fields: string[]) => {
    const obj = gAny(n) as Record<string, unknown>;
    for (const f of fields) delete obj[f];
    return canonicalJSONV2(obj);
  };
  if (field === "signature") return drop(root, "signature");
  if (field === "challenge_sig") return drop(root, "delegations", "challenge_sig");
  if (field === "old_signature" || field === "new_signature") return drop(root, "old_signature", "new_signature");
  const m = /^delegations\[(\d+)\]\.signature$/.exec(field);
  if (m) {
    const certs = (root as Extract<JNode, { k: "obj" }>).m.get("delegations")!;
    assert.equal(certs.k, "arr");
    return drop((certs as Extract<JNode, { k: "arr" }>).a[Number(m[1])]!, "signature");
  }
  if (field.startsWith("party_signatures[")) return transactionReceiptV2SignBytes(await decodeTransactionReceiptV2(wire));
  assert.fail(`unknown signature field ${field}`);
}

function lp(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(8 + b.length);
  new DataView(out.buffer).setBigUint64(0, BigInt(b.length));
  out.set(b, 8);
  return out;
}

async function transactionPartyDigest(wire: Uint8Array, name: string, txContextHex: string): Promise<string> {
  const r = await decodeTransactionReceiptV2(wire);
  const enc = (s: string) => new TextEncoder().encode(s);
  const txContext = sha256(new Uint8Array([
    ...enc("ratify/transaction-context/v2"), ...lp(enc(r.transaction_id)), ...lp(enc(r.terms_schema_uri)), ...sha384(r.terms_canonical_json),
  ]));
  assert.equal(hexOf(txContext), txContextHex, "transaction context differs");
  const [partyID, field] = [name.slice(0, name.indexOf(".")), name.slice(name.indexOf(".") + 1)];
  const p = r.parties.find((x) => x.party_id === partyID);
  assert.ok(p, `unknown party ${partyID}`);
  const req = sha256(new Uint8Array([...enc("ratify/transaction-party-request/v2"), ...lp(txContext), ...lp(enc(p.required_scope))]));
  switch (field) {
    case "transaction_party_request_hash_hex": return hexOf(req);
    case "session_context_hex":
      return hexOf(buildSessionContextV2({
        verifier_id: p.verifier_id, workspace_id: p.workspace_id, agent_id: p.agent_id, session_id: p.session_id,
        invocation_id: p.invocation_id, request_hash: req,
      }));
    case "proof_bundle_hash": return bundleHashV2(p.proof_bundle!);
  }
  assert.fail(`unknown transaction digest ${name}`);
}

async function checkObjectDigests(o: Any, wire: Uint8Array): Promise<void> {
  for (const [name, want] of Object.entries(o.digests as Record<string, string>)) {
    let got: string;
    switch (name) {
      case "issuer_key_id_v2":
        got = deriveKeyIDV2(decodeDelegationCertV2(wire).issuer_pub_key);
        break;
      case "subject_key_id_v2":
        got = deriveKeyIDV2(decodeDelegationCertV2(wire).subject_pub_key);
        break;
      case "delegation_digest_hex":
        got = hexOf(decodeProofBundleV2(wire).delegation_digest);
        break;
      case "bundle_hash_v2":
        got = bundleHashV2(decodeProofBundleV2(wire));
        break;
      case "session_context_hex": {
        const b = decodeProofBundleV2(wire);
        const ctx = buildSessionContextV2({
          verifier_id: b.verifier_id, workspace_id: "00000000-0000-4000-8000-000000000001", agent_id: b.agent_id,
          session_id: "session-01", invocation_id: "invocation-01",
          request_hash: operationContextV2Hash({ required_scope: "data:read", operation: "records.get", resource_id: "customer/123", requested_path: "/v1/customers/123" }),
        });
        assert.ok(b.session_context && eqBytes(b.session_context, ctx), "bundle session_context does not match the recomputed fixture context");
        got = hexOf(ctx);
        break;
      }
      case "challenge_claim_digest_hex":
        got = hexOf(challengeClaimDigestV2(decodeProofBundleV2(wire).challenge));
        break;
      case "claim_id":
        got = protocolClaimIDV2(o.digests.claim_verifier_namespace, Number(o.digests.claim_replay_epoch), decodeProofBundleV2(wire).challenge);
        break;
      case "claim_verifier_namespace":
      case "claim_replay_epoch":
      case "transaction_context_hex":
        continue;
      case "receipt_outbox_body_b64":
        got = base64Encode(verificationReceiptV2Body(decodeVerificationReceiptV2(wire)));
        break;
      case "status_evidence_digest":
        got = "sha384:" + hexOf(o.kind === "revocation_list"
          ? statusEvidenceDigestV2(3, decodeRevocationListV2(wire))
          : statusEvidenceDigestV2(5, decodeRevocationPushV2(wire)));
        break;
      case "statement_body_digest_hex":
        if (o.kind === "key_rotation_statement") got = hexOf(keyRotationStatementV2Digest(decodeKeyRotationStatementV2(wire)));
        else if (o.kind === "witness_entry") got = hexOf(witnessEntryV2Digest(decodeWitnessEntryV2(wire)));
        else got = hexOf(verificationReceiptV2Digest(decodeVerificationReceiptV2(wire)));
        break;
      default:
        assert.ok(name.startsWith("party-"), `unknown digest ${name}`);
        got = await transactionPartyDigest(wire, name, o.digests.transaction_context_hex);
    }
    assert.equal(got, want, `${o.name}: digest ${name}`);
  }
}

test("v2 conformance: objects.json (re-encode, projections, transcripts, signatures, digests)", async (t) => {
  const fx = await fixturePromise;
  const seenCodes = new Set<number>();
  assert.ok(objectsFile.objects.length > 0);
  for (const o of objectsFile.objects) {
    await t.test(o.name, async () => {
      const wire = unb64(o.wire_b64);
      assert.ok(eqBytes(await reencode(o.kind, wire), wire), "re-encoding is not byte-identical");
      await verifyObject(fx, o.kind, wire, null, o.verify);
      for (const s of o.signatures) {
        seenCodes.add(s.object_type_code);
        const signable = unb64(s.signable_b64);
        assert.equal(utf8(await projection(wire, s.field)), utf8(signable), `${s.field}: signable projection`);
        assert.equal(hexOf(sha384(signable)), s.signable_sha384_hex, `${s.field}: signable SHA-384`);
        const m = v2SigningMessage(s.object_type_code, signable);
        assert.ok(eqBytes(m, unb64(s.message_b64)) && m.length === 77, `${s.field}: transcript M`);
        const ctx = utf8(v2MLDSAContext(s.object_type_code));
        assert.equal(s.mldsa_context, ctx, `${s.field}: ML-DSA context`);
        assert.equal(ctx.length, 22);
        assert.equal(fx.id.get(s.signer), s.signer_key_id_v2, `${s.field}: signer key ID`);
        const signer = fx.pair.get(s.signer)!;
        const tr = shake256(signer.publicKey.ml_dsa_65, { dkLen: 64 });
        const ctxBytes = new TextEncoder().encode(ctx);
        const mu = shake256(new Uint8Array([...tr, 0, ctxBytes.length, ...ctxBytes, ...m]), { dkLen: 64 });
        assert.ok(eqBytes(tr, unb64(s.mldsa_tr_b64)) && eqBytes(mu, unb64(s.mldsa_mu_b64)), `${s.field}: external-mu tr/mu`);
        const text = utf8(wire);
        assert.ok(text.includes(s.signature.ml_dsa_65) && text.includes(s.signature.ed25519), `${s.field}: pinned signature is carried by the wire object`);
        // Deterministic signing reproduces both components byte-for-byte.
        const resigned = await signV2Statement(s.object_type_code, signable, signer, { deterministic: true });
        assert.equal(base64Encode(resigned.ed25519), s.signature.ed25519, `${s.field}: Ed25519 signature bytes`);
        assert.equal(base64Encode(resigned.ml_dsa_65), s.signature.ml_dsa_65, `${s.field}: ML-DSA-65 signature bytes`);
      }
      await checkObjectDigests(o, wire);
    });
  }
  for (let code = 1; code <= 9; code++) assert.ok(seenCodes.has(code), `objects.json has no signature for object_type_code ${code}`);
});

test("v2 conformance: object-negatives.json", async (t) => {
  const fx = await fixturePromise;
  const f = load("object-negatives.json");
  const kinds = new Map<string, number>();
  assert.ok(f.vectors.length > 0);
  for (const v of f.vectors) {
    kinds.set(v.kind, (kinds.get(v.kind) ?? 0) + 1);
    await t.test(v.name, async () => {
      const bundle = v.bundle_b64 ? unb64(v.bundle_b64) : null;
      const got = await classOfAsync(() => verifyObject(fx, v.kind, unb64(v.wire_b64), bundle, v.verify));
      assert.notEqual(got, "", `accepted; want ${v.expected_error_class} (${v.mutation})`);
      assert.equal(got, v.expected_error_class, `${v.mutation}`);
    });
  }
  for (const kind of ["delegation_certificate", "proof_bundle", "revocation_list", "revocation_push", "key_rotation_statement", "witness_entry", "transaction_receipt", "verification_receipt", "receipt_bundle_binding"]) {
    assert.ok((kinds.get(kind) ?? 0) > 0, `no negative vectors for ${kind}`);
  }
});

// ---------------------------------------------------------------------------
// Verifier ordering

interface Counts {
  receiver_binding: number;
  claim: number;
  trust: number;
  status: number;
  audience: number;
  rate: number;
  finalize: number;
}

async function runOrderingVector(v: Any, bundle: Uint8Array): Promise<void> {
  const counts: Counts = { receiver_binding: 0, claim: 0, trust: 0, status: 0, audience: 0, rate: 0, finalize: 0 };
  const req: V2VerifyRequest = {
    bundle, expected: null, contextPolicy: null, requiredScope: v.required_scope, verifierNamespace: v.configured_namespace,
    replayEpoch: v.configured_replay_epoch, now: v.now, maxChallengeAgeSeconds: v.max_challenge_age_seconds,
    futureSkewSeconds: v.future_skew_seconds, statusRoles: { statusKeyIssuers: null, currentStatusKeyIDs: null, reservedKeyIDs: null },
  };
  const e = v.expected_challenge;
  if (e) {
    const exp: ExpectedChallengeV2 = {
      value: unb64(e.value_b64), issuedAt: e.issued_at, expiresAt: e.expires_at, verifierNamespace: e.verifier_namespace,
      replayEpoch: e.replay_epoch, verifierID: e.verifier_id,
    };
    if (e.expected_agent_id !== null && e.expected_agent_id !== undefined) {
      exp.expectedAgentID = e.expected_agent_id;
      exp.expectedAgentPublicKey = e.expected_agent_public_key ? pubOf(e.expected_agent_public_key) : null;
    }
    if (e.expected_receiver_id !== null && e.expected_receiver_id !== undefined) exp.expectedReceiverID = e.expected_receiver_id;
    if (e.expected_session_context_b64 !== null && e.expected_session_context_b64 !== undefined) {
      exp.expectedSessionContext = unb64(e.expected_session_context_b64);
    }
    req.expected = exp;
  }
  const p = v.context_policy;
  if (p) {
    const expected = p.expected_session_context_b64 === null || p.expected_session_context_b64 === undefined ? null : unb64(p.expected_session_context_b64);
    req.contextPolicy = newV2ContextPolicy(p.profile, p.require_bound, p.required_fields, expected);
    assert.equal(req.contextPolicy.digest, p.digest, "context policy digest");
  }
  const rc = v.request_context;
  if (rc) req.context = { has_resource: rc.has_resource, requested_resource_id: rc.requested_resource_id, requested_path: rc.requested_path };
  req.statusRoles = {
    statusKeyIssuers: new Map(Object.entries(v.status_roles.status_key_issuers ?? {})),
    currentStatusKeyIDs: new Map(Object.entries(v.status_roles.current_status_key_ids ?? {})),
    reservedKeyIDs: new Set(v.status_roles.reserved_key_ids ?? []),
  };
  let finalBody: Uint8Array | null = null;
  const store: ClaimStoreV2 = {
    async claimV2(_claim: V2ChallengeClaim): Promise<V2ClaimResult> {
      counts.claim++;
      switch (v.claim_store) {
        case "create": return { disposition: "created", claimedAt: v.now, ownerToken: new Uint8Array(32).fill(7) };
        case "proof_conflict": throw ErrV2ClaimProofConflict;
        case "in_progress": return { disposition: "in_progress", claimedAt: v.now };
        case "terminal_replay": return { disposition: "terminal_replay", claimedAt: v.now };
      }
      throw new Error("scripted claim store unavailable");
    },
    async finalizeV2Claim(_id, _owner, _result, receiptBody) {
      counts.finalize++;
      finalBody = Uint8Array.from(receiptBody);
      return true;
    },
    async recoverInterruptedV2Claim() {
      throw new Error("not used by conformance vectors");
    },
  };
  const cb: V2VerifyCallbacks = {
    claimStore: store,
    trust: async () => {
      counts.trust++;
      if (!v.trust || !v.trust.available) return { available: false, rootID: "", rootKey: null };
      return { available: true, rootID: v.trust.root_key_id, rootKey: pubOf(v.trust.root_public_key) };
    },
    status: async (ref): Promise<RevocationStatusResultV2> => {
      counts.status++;
      const r = v.status?.[`${ref.issuerID}/${ref.certID}`];
      if (!r) return { status: "indeterminate", reason: "unavailable", evidence: [], freshUntil: 0 };
      return { status: r.status, reason: r.reason ?? "", freshUntil: r.fresh_until ?? 0, evidence: (r.evidence ?? []).map((x: StatusEvidenceEntryV2) => ({ ...x })) };
    },
    audience: async (): Promise<V2AudienceMembership[]> => {
      counts.audience++;
      return (v.audience_memberships ?? []).map((m: Any) => ({
        delegationIndex: m.delegation_index, constraintIndex: m.constraint_index, receiverID: m.receiver_id,
        trustDomainIDs: m.trust_domain_ids, issuedAt: m.issued_at, expiresAt: m.expires_at, evidenceDigest: m.evidence_digest,
      }));
    },
  };
  if (v.receiver_binding_hook === "accept" || v.receiver_binding_hook === "reject") {
    cb.receiverBinding = () => {
      counts.receiver_binding++;
      if (v.receiver_binding_hook === "reject") throw new Error("application receiver binding rejected");
    };
  } else {
    assert.equal(v.receiver_binding_hook, "absent", `unknown receiver_binding_hook ${v.receiver_binding_hook}`);
  }
  let rateBatch: V2RateReservation[] | null = null;
  if (v.rate !== "absent") {
    cb.rate = {
      async reserveV2RateBatch(_claimID, _owner, _hash, batch) {
        counts.rate++;
        rateBatch = batch.map((b) => ({ ...b }));
        if (v.rate === "reserve") return;
        if (v.rate === "exceeded") throw ErrV2RateLimitExceeded;
        throw new Error("scripted rate store unavailable");
      },
    };
  }
  const outcome = await verifyProofBundleV2(req, cb);
  assert.equal(outcome.evaluationError, null, `evaluation did not terminate: ${outcome.evaluationError?.message}`);
  const want = v.expected;
  assert.equal(outcome.stage, want.stage, `stage (class ${outcome.errorClass}, err ${outcome.error?.message}, ${outcome.decision}/${outcome.reason})`);
  assert.equal(outcome.errorClass, want.error_class ?? "", `error class (${outcome.error?.message})`);
  if (want.disposition) assert.equal(outcome.disposition, want.disposition, "disposition");
  assert.deepEqual(counts, want.callback_counts, "callback counts");
  if (want.stage !== "terminal") return;
  const r = outcome.receipt!;
  assert.deepEqual(
    [outcome.decision, outcome.reason, outcome.identityStatus, r.trust_assessment, r.status_assessment, r.context_assessment],
    [want.decision, want.decision_reason, want.identity_status, want.trust_assessment, want.status_assessment, want.context_assessment],
    "terminal tuple",
  );
  assert.equal(r.context_policy_digest, want.context_policy_digest ?? null, "context_policy_digest");
  assert.equal(utf8(outcome.receiptBody!), utf8(unb64(want.receipt_body_b64)), "receipt body");
  assert.ok(finalBody !== null && eqBytes(finalBody, outcome.receiptBody!), "finalized body differs from the outcome body");
  assert.equal(outcome.allowValidUntil, want.allow_valid_until ?? 0, "allow_valid_until");
  if ((want.rate_batch ?? []).length !== 0) {
    assert.ok(rateBatch !== null, "rate batch not reserved");
    assert.deepEqual(
      (rateBatch as V2RateReservation[]).map((b) => [b.issuerID, b.certID, b.windowS, b.limit]),
      want.rate_batch.map((b: Any) => [b.issuer_id, b.cert_id, b.window_s, b.limit]),
      "rate batch",
    );
  }
}

test("v2 conformance: verifier-ordering.json", async (t) => {
  const f = load("verifier-ordering.json");
  assert.ok(f.vectors.length > 0, "no ordering vectors");
  for (const v of f.vectors) {
    const bundle = f.bundles_b64[v.bundle];
    assert.ok(bundle, `${v.name}: unknown bundle ${v.bundle}`);
    await t.test(v.name, () => runOrderingVector(v, unb64(bundle)));
  }
});

// ---------------------------------------------------------------------------
// Status sequences

const policyOf = (p: Any): RevocationStatusPolicyV2 => ({
  maxListLifetimeSeconds: p.max_list_lifetime_seconds, maxStatusAgeSeconds: p.max_status_age_seconds, clockSkewSeconds: p.clock_skew_seconds,
});

function checkStatusState(where: string, s: RevocationStatusStateV2, w: Any): void {
  const pairs: [string, unknown, unknown][] = [
    ["has_floor", s.hasFloor, w.has_floor], ["floor", s.floor, w.floor], ["max_observed_sequence", s.maxObservedSequence, w.max_observed_sequence],
    ["fork_sequence", s.forkSequence, w.fork_sequence], ["reconciliation_required", s.reconciliationRequired, w.reconciliation_required],
    ["future_dated_object_observed", s.futureDatedObjectObserved, w.future_dated_object_observed],
    ["accepted_set", s.acceptedCertIDs, w.accepted_set], ["deny_union", s.denyUnionCertIDs, w.deny_union],
  ];
  for (const [name, got, want] of pairs) if (want !== undefined && want !== null) assert.deepEqual(got, want, `${where}: ${name}`);
}

test("v2 conformance: status-sequences.json", async (t) => {
  const fx = await fixturePromise;
  const f = load("status-sequences.json");
  assert.ok(f.scenarios.length > 0, "no status scenarios");
  for (const sc of f.scenarios) {
    await t.test(sc.name, async () => {
      let state = emptyRevocationStatusStateV2();
      for (let i = 0; i < sc.steps.length; i++) {
        const step = sc.steps[i];
        const key = pub(fx, step.status_key);
        const policy = policyOf(step.policy ?? sc.policy);
        const where = `step ${i} ${step.op} ${step.label ?? ""}`;
        if (step.op === "query") {
          const r = await revocationStatusForCertV2(state, sc.issuer_id, step.cert_id, step.status_key_epoch, key, policy, step.now);
          assert.deepEqual([r.status, r.reason], [step.expect_result.status, step.expect_result.reason ?? ""], `${where}: result`);
          assert.deepEqual(r.evidence, step.expect_result.evidence, `${where}: evidence`);
          continue;
        }
        let next: RevocationStatusStateV2 | null = null;
        let err: unknown = null;
        try {
          if (step.op === "apply_list") next = await applyRevocationListV2(state, decodeRevocationListV2(unb64(step.wire_b64)), sc.issuer_id, step.status_key_epoch, key, policy, step.now);
          else if (step.op === "apply_push") next = await applyRevocationPushV2(state, decodeRevocationPushV2(unb64(step.wire_b64)), sc.issuer_id, step.status_key_epoch, key, policy, step.now);
          else if (step.op === "transition_epoch") next = transitionRevocationStatusEpochV2(state, sc.issuer_id, step.status_key_epoch, key);
          else assert.fail(`unknown op ${step.op}`);
        } catch (e) {
          err = e;
        }
        if (step.expect_error_class) {
          assert.equal(v2ErrorClassOf(err), step.expect_error_class, `${where}: error class (${(err as Error)?.message})`);
          continue;
        }
        assert.equal(err, null, `${where}: ${(err as Error)?.message}`);
        state = next!;
        if (step.expect_state) checkStatusState(where, state, step.expect_state);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Witness and receipt logs

test("v2 conformance: log-sequences.json", async (t) => {
  const fx = await fixturePromise;
  const f = load("log-sequences.json");
  assert.equal(f.scenarios.length, 2, "want witness and receipt log scenarios");
  for (const sc of f.scenarios) {
    await t.test(sc.name, async () => {
      const genesis = (logID: string): WitnessV2Head => ({ logID, sequence: 0, headHash: new Uint8Array(48), acceptedDigests: new Map(), frozen: false });
      let head = genesis(sc.initial_log_id);
      for (let i = 0; i < sc.steps.length; i++) {
        const step = sc.steps[i];
        if (step.op === "recover") {
          head = genesis(step.log_id);
          continue;
        }
        const wire = unb64(step.wire_b64);
        let got = "";
        let digest: Uint8Array | null = null;
        let seq = 0;
        try {
          let result: V2AppendResult;
          if (sc.kind === "witness_entry") {
            const entry = decodeWitnessEntryV2(wire);
            digest = witnessEntryV2Digest(entry);
            seq = entry.sequence;
            result = await verifyWitnessEntryV2(entry, head, pub(fx, step.key));
          } else {
            const r = decodeVerificationReceiptV2(wire);
            digest = verificationReceiptV2Digest(r);
            seq = r.sequence;
            result = await verifyVerificationReceiptV2(r, pub(fx, step.key), { ...head, verifierID: sc.verifier_id });
          }
          got = result;
        } catch (err) {
          got = v2ErrorClassOf(err);
        }
        assert.equal(got, step.expect, `step ${i} ${step.label}`);
        if (got === "appended") {
          head.sequence = seq;
          head.headHash = digest!;
          head.acceptedDigests.set(seq, digest!);
        } else if (got === "log_fork") {
          head.frozen = true;
        }
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Rotation sequences

test("v2 conformance: rotation-sequences.json", async (t) => {
  const fx = await fixturePromise;
  const f = load("rotation-sequences.json");
  assert.ok(f.scenarios.length > 0, "no rotation scenarios");
  for (const sc of f.scenarios) {
    await t.test(sc.name, async () => {
      let journal: KeyRotationV2Journal = newKeyRotationV2Journal(sc.authority_id, sc.recovery_epoch, sc.role, pub(fx, sc.genesis_key));
      for (let i = 0; i < sc.steps.length; i++) {
        const step = sc.steps[i];
        let got = "";
        let err: unknown = null;
        if (step.op === "recover") {
          try {
            journal = recoverKeyRotationV2(journal, step.new_recovery_epoch, pub(fx, step.new_genesis_key));
            got = "recovered";
          } catch (e) {
            err = e;
            got = v2ErrorClassOf(e);
          }
        } else {
          const s = decodeKeyRotationStatementV2(unb64(step.wire_b64));
          const out = await acceptKeyRotationStatementV2(s, journal, step.now, sc.future_skew_seconds);
          journal = out.journal;
          err = out.error ?? null;
          got = out.error ? v2ErrorClassOf(out.error) : out.result!;
        }
        assert.equal(got, step.expect, `step ${i} ${step.label} (${(err as Error)?.message})`);
        assert.equal(journal.state.sequence, step.expect_sequence, `step ${i}: sequence`);
        assert.ok(eqBytes(journal.state.currentKey.ml_dsa_65, pub(fx, step.expect_current_key).ml_dsa_65), `step ${i}: current key`);
        assert.equal(journal.state.recoveryEpoch, step.expect_recovery_epoch, `step ${i}: recovery epoch`);
        assert.equal(journal.frozen, step.expect_frozen, `step ${i}: frozen`);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Hand-maintained and legacy-positive files

test("v2 conformance: key-rotation-signature.json", async () => {
  const f = load("key-rotation-signature.json");
  assert.equal(f.version, 2);
  assert.equal(f.object_type_code, 4);
  assert.ok(f.continuation && f.continuation.sequence === 2, "vector lacks a sequence-2 continuation");
  let journal: KeyRotationV2Journal | null = null;
  let priorDigest: string | null = null;
  for (const v of [f, f.continuation]) {
    const oldPair = await hybridKeypairFromSeeds(hex(v.old_key_seeds.ed25519), hex(v.old_key_seeds.ml_dsa_65));
    const newPair = await hybridKeypairFromSeeds(hex(v.new_key_seeds.ed25519), hex(v.new_key_seeds.ml_dsa_65));
    assert.ok(eqBytes(oldPair.publicKey.ml_dsa_65, unb64(v.old_key.ml_dsa_65)) && eqBytes(newPair.publicKey.ed25519, unb64(v.new_key.ed25519)), "seed-derived keys");
    const stmt: KeyRotationStatementV2 = {
      version: v.version, authority_id: v.authority_id, recovery_epoch: v.recovery_epoch, role: v.role, sequence: v.sequence,
      previous_statement_hash: unb64(v.previous_statement_hash), old_key: oldPair.publicKey, new_key: newPair.publicKey,
      old_key_id: v.old_key_id, new_key_id: v.new_key_id, issued_at: v.issued_at, not_before: v.not_before,
      old_signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) }, new_signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
    };
    assert.equal(utf8(keyRotationStatementV2SignBytes(stmt)), utf8(unb64(v.signable_bytes)), "signable bytes");
    assert.equal(utf8(v2MLDSAContext(V2_OBJECT_TYPE.keyRotationAuthorization)), v.old_mldsa_context);
    assert.equal(utf8(v2MLDSAContext(V2_OBJECT_TYPE.keyRotationProofOfPossession)), v.new_mldsa_context);
    const signed = await signKeyRotationStatementV2(stmt, oldPair, newPair, { deterministic: true });
    assert.equal(base64Encode(signed.old_signature.ed25519), v.old_signature.ed25519, "old Ed25519 signature");
    assert.equal(base64Encode(signed.old_signature.ml_dsa_65), v.old_signature.ml_dsa_65, "old ML-DSA signature");
    assert.equal(base64Encode(signed.new_signature.ed25519), v.new_signature.ed25519, "new Ed25519 signature");
    assert.equal(base64Encode(signed.new_signature.ml_dsa_65), v.new_signature.ml_dsa_65, "new ML-DSA signature");
    assert.equal(hexOf(keyRotationStatementV2Digest(signed)), v.statement_body_digest, "statement body digest");
    const wire = unb64(v.wire);
    const decoded = decodeKeyRotationStatementV2(wire);
    assert.ok(eqBytes(encodeKeyRotationStatementV2(decoded), wire), "wire is canonical and stable");
    assert.ok(eqBytes(encodeKeyRotationStatementV2(signed), wire), "signed statement encodes to the vector wire");
    if (priorDigest !== null) assert.equal(hexOf(decoded.previous_statement_hash), priorDigest, "continuation links to the genesis digest");
    if (journal === null) journal = newKeyRotationV2Journal(v.authority_id, v.recovery_epoch, v.role, oldPair.publicKey);
    const out = await acceptKeyRotationStatementV2(decoded, journal, Math.max(v.issued_at, v.not_before), 0);
    assert.equal(out.error, undefined, out.error?.message);
    assert.equal(out.result, "appended");
    journal = out.journal;
    priorDigest = v.statement_body_digest;
  }
});

test("v2 conformance: delegation-signature.json (typed statement API)", async () => {
  const f = load("delegation-signature.json");
  const signable = unb64(f.signable_bytes);
  assert.ok(eqBytes(v2SigningMessage(f.object_type_code, signable), unb64(f.message)));
  assert.ok(eqBytes(v2MLDSAContext(f.object_type_code), unb64(f.mldsa_context)));
  assert.ok(eqBytes(v2MLDSAContext(2), unb64(f.alternate_mldsa_context)));
  const key = pubOf(f.issuer_public_key);
  assert.equal(deriveKeyIDV2(key), f.key_id_v2);
  const { verifyV2Statement } = await import("../src/protocol_v2_wire.js");
  const sig = { ed25519: unb64(f.signature.ed25519), ml_dsa_65: unb64(f.signature.ml_dsa_65) };
  await verifyV2Statement(f.object_type_code, signable, sig, key);
  assert.equal(await classOfAsync(() => verifyV2Statement(2, signable, sig, key)), "invalid_signature");
  assert.equal(await classOfAsync(() => verifyV2Statement(0x000a, signable, sig, key)), "unsupported_object_type");
});

test("v2 conformance: challenge-claim.json", () => {
  const f = load("challenge-claim.json");
  const challenge = hex(f.challenge_hex);
  assert.equal(hexOf(challengeClaimDigestV2(challenge)), f.expected_challenge_claim_digest_hex);
  assert.equal(protocolClaimIDV2(f.claim_id_input.verifier_namespace, f.claim_id_input.replay_epoch, challenge), f.expected_claim_id);
  for (const c of f.additional_claim_id_cases) assert.equal(protocolClaimIDV2(c.verifier_namespace, c.replay_epoch, challenge), c.expected_claim_id);
});

test("v2 conformance: operation-session-context.json (context policy digest)", () => {
  const f = load("operation-session-context.json");
  const p = f.context_policy;
  const policy = newV2ContextPolicy(p.profile, p.require_bound, p.required_fields, new Uint8Array(32));
  assert.equal(policy.digest, f.context_policy_digest);
  const ctx = buildSessionContextV2({
    verifier_id: f.input.verifier_id, workspace_id: f.input.workspace_id, agent_id: f.input.agent_id,
    session_id: f.input.session_id, invocation_id: f.input.invocation_id, request_hash: hex(f.input.request_hash_hex),
  });
  assert.equal(hexOf(ctx), f.expected_session_context_hex);
});

export type { ProofBundleV2 };
