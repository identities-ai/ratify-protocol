// Ratify Protocol v2 quickstart: delegate, present, verify, publish, release.
//
// DEVELOPMENT ONLY. This program uses the in-memory reference stores from
// @identities-ai/ratify-protocol/v2/reference (claim store, receipt log,
// checkpoint, journal and challenge issuance store). They exist for tests and
// examples. A production verifier supplies durable Part B stores and an
// independent checkpoint (SPEC-v2 §7).
//
// Run from this directory: node quickstart.ts
import { generateHybridKeypair } from "@identities-ai/ratify-protocol";
import {
  TZDB_VERSION_V2,
  configureStatusKeyEpochV2,
  decodeVerificationReceiptV2,
  encodeProofBundleV2,
  encodeRevocationListV2,
  issueChallengeV2,
  keyIDV2,
  loadExpectedChallengeV2,
  newV2ContextPolicy,
  newV2StatusPublisherWithKey,
  recordSecurityKeyRoleV2,
  releaseV2Decision,
  signDelegationCertV2,
  signProofBundleV2,
  verifyProofBundleV2,
  type DelegationCertV2,
  type HybridKeyPairV2,
  type V2VerifyOutcome,
} from "@identities-ai/ratify-protocol/v2";
import { ChallengeIssuanceStoreTestOnly, JournalStoreTestOnly, StoreTestOnly } from "@identities-ai/ratify-protocol/v2/reference";

const start = 1800000000; // fixed clock so the output is reproducible
const namespace = "quickstart";
const epoch = 1;
const logID = "00000000000000000000000000000001";
const unsigned = { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) }; // replaced when signed

console.log("Ratify Protocol v2 quickstart");
console.log("development only: in-memory reference stores");

// 1. Keys. Every party holds a hybrid Ed25519 + ML-DSA-65 key. The status
// key is separate from the root key that issues delegations.
const root: HybridKeyPairV2 = await generateHybridKeypair();
const agent: HybridKeyPairV2 = await generateHybridKeypair();
const status: HybridKeyPairV2 = await generateHybridKeypair();
const verifier: HybridKeyPairV2 = await generateHybridKeypair();
const rootID = keyIDV2(root.publicKey);
const agentID = keyIDV2(agent.publicKey);
const verifierID = keyIDV2(verifier.publicKey);
console.log(`keys: root, agent, status and verifier generated (key IDs are ${rootID.length} hex characters)`);

// 2. The root delegates payments:send to the agent, capped at 50.00 USD per
// action (amounts are integer micro-units in v2).
const cert: DelegationCertV2 = await signDelegationCertV2({
  version: 2, cert_id: "quickstart-cert-1",
  issuer_id: rootID, issuer_pub_key: root.publicKey,
  subject_id: agentID, subject_pub_key: agent.publicKey,
  scope: ["payments:send"],
  constraints: [{ type: "max_amount", currency: "USD", max_amount_micros: 50_000_000 }],
  issued_at: start, expires_at: start + 86400,
  signature: unsigned,
}, root);
console.log("delegation: scope=payments:send max_amount=50000000 USD micros lifetime=86400s");

// 3. Verifier state: the reference store is the claim store, receipt log,
// checkpoint and authoritative clock. The journal records key roles and the
// root's status key.
const store = new StoreTestOnly(start, 30, logID, verifier);
const journal = new JournalStoreTestOnly();
await recordSecurityKeyRoleV2(journal, "issuer", root.publicKey);
await recordSecurityKeyRoleV2(journal, "delegation", agent.publicKey);
await recordSecurityKeyRoleV2(journal, "verifier", verifier.publicKey);
await configureStatusKeyEpochV2(journal, rootID, 1, status.publicKey);

// 4. The root's status publisher signs a genesis revocation list (no
// revocations) under the separate status key.
const publisher = await newV2StatusPublisherWithKey(journal, root.publicKey, status, 3600);
const genesis = await publisher.genesis(start);
const statusWire = encodeRevocationListV2(genesis.list);
console.log(`status: genesis list signed by the status key (sequence ${genesis.state.sequence}, ${genesis.state.revoked.length} revoked)`);

// 5. The verifier issues a challenge. The helper persists the record before
// it returns the challenge.
const issuance = new ChallengeIssuanceStoreTestOnly();
const challenge = await issueChallengeV2({ clock: store, store: issuance }, {
  verifierNamespace: namespace, replayEpoch: epoch, verifierID,
  lifetimeSeconds: 120, expectedAgentID: agentID, expectedAgentPublicKey: agent.publicKey,
});
console.log(`challenge: issued and persisted, expires in ${challenge.expiresAt - challenge.issuedAt}s`);

// 6. The agent signs a proof bundle over the challenge.
store.setTime(start + 2);
const bundle = await signProofBundleV2({
  version: 2, verifier_id: verifierID, agent_id: agentID, agent_pub_key: agent.publicKey,
  delegations: [cert], delegation_digest: new Uint8Array(0),
  challenge: challenge.value, challenge_at: challenge.issuedAt, challenge_sig: unsigned,
  session_context: null, stream_id: null, stream_seq: null,
}, agent);
const bundleWire = encodeProofBundleV2(bundle);
console.log(`proof: agent signed the presentation (${bundle.delegations!.length} delegation)`);

// 7. Verify. The verifier loads the issuance record for the presented
// challenge, then runs the full v2 decision path.
async function verify(): Promise<V2VerifyOutcome> {
  const expected = await loadExpectedChallengeV2(issuance, namespace, epoch, bundle.challenge);
  return verifyProofBundleV2({
    bundle: bundleWire, expected, contextPolicy: newV2ContextPolicy("example.quickstart/v1", false, null, null),
    requiredScope: "payments:send", verifierNamespace: namespace, replayEpoch: epoch,
    now: store.now(), maxChallengeAgeSeconds: 300, futureSkewSeconds: 5,
    context: { hasAmount: true, requestedAmountMicros: 12_500_000, requestedCurrency: "USD" },
    tzdbVersion: TZDB_VERSION_V2,
    statusKeys: new Map([[rootID, { epoch: 1, key: status.publicKey }]]),
    statusPolicy: { maxListLifetimeSeconds: 3600, maxStatusAgeSeconds: 3600, clockSkewSeconds: 5 },
  }, {
    claimStore: store,
    // Trust is pinned to the complete root public key, never a key ID.
    trust: (chain) => chain[chain.length - 1]!.issuer_id === rootID
      ? { outcome: "trusted", rootKey: root.publicKey }
      : { outcome: "untrusted" },
    statusEvidence: async () => ({ objects: [{ objectType: 3, wire: statusWire }] }),
    statusJournal: journal,
  });
}
const outcome = await verify();
if (outcome.stage !== "committed" || !outcome.committed) throw new Error(`verify stopped at ${outcome.stage}: ${outcome.error}`);
console.log("verify: stage=committed (not actionable until released)");

// 8. Publish the signed receipt to the log; the checkpoint acknowledges it.
const receiptWire = await store.publishV2Receipt(outcome.committed.claimID(), outcome.committed.receiptBody());
const receipt = decodeVerificationReceiptV2(receiptWire);
console.log(`receipt: published at log sequence ${receipt.sequence}`);
const ack = await store.getV2Acknowledgement(logID, receipt.sequence);
console.log(`checkpoint: acknowledged sequence ${ack.sequence}`);

// 9. Release. Only a released decision is actionable.
const result = await releaseV2Decision(outcome.committed, receiptWire, {
  verifierPublicKey: verifier.publicKey, logID, claimStore: store, checkpoint: store,
});
if (result.status !== "released" || !result.decision) throw new Error(`release ${result.status}: ${result.reason}`);
const decision = result.decision;
console.log(`release: status=${result.status} decision=${decision.decision()} reason=${decision.reason()}`);
console.log(`granted scope: ${decision.grantedScope().join(",")}`);

// 10. Gate the side effect on allowed() at the receiver's authoritative time.
console.log(`allowed now: ${await decision.allowed(store)}`);

// 11. Presenting the same proof again is a replay and is never evaluated.
store.setTime(start + 3);
const replay = await verify();
console.log(`replay: stage=${replay.stage} disposition=${replay.disposition}`);

// 12. The released allow ends at the challenge expiry (an exclusive deadline).
store.setTime(challenge.expiresAt);
console.log(`allowed at challenge expiry: ${await decision.allowed(store)}`);
