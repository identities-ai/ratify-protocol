// Ratify Protocol v2 signed status: a status publisher under a separate
// status key, journal ingestion, and a revocation that turns a later
// verification into deny.
//
// DEVELOPMENT ONLY. This program uses the in-memory reference stores from
// @identities-ai/ratify-protocol/v2/reference. A production verifier supplies
// durable Part B stores, an anchored journal store and an independent
// checkpoint (SPEC-v2 §7).
//
// Run from this directory: node signed_status.ts
import { generateHybridKeypair } from "@identities-ai/ratify-protocol";
import {
  TZDB_VERSION_V2,
  applyRevocationListToJournalV2,
  applyRevocationPushToJournalV2,
  configureStatusKeyEpochV2,
  encodeProofBundleV2,
  encodeRevocationListV2,
  encodeRevocationPushV2,
  issueChallengeV2,
  keyIDV2,
  loadExpectedChallengeV2,
  newV2ContextPolicy,
  newV2StatusPublisherWithKey,
  recordSecurityKeyRoleV2,
  releaseV2Decision,
  revocationStatusFromJournalV2,
  signDelegationCertV2,
  signProofBundleV2,
  v2ErrorClassOf,
  verifyProofBundleV2,
  type HybridKeyPairV2,
  type RevocationStatusPolicyV2,
  type V2StatusEvidenceObject,
} from "@identities-ai/ratify-protocol/v2";
import { ChallengeIssuanceStoreTestOnly, JournalStoreTestOnly, StoreTestOnly } from "@identities-ai/ratify-protocol/v2/reference";

const start = 1800000000;
const namespace = "signed-status";
const epoch = 1;
const logID = "00000000000000000000000000000002";
const certID = "status-demo-cert-1";
const unsigned = { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) }; // replaced when signed

console.log("Ratify Protocol v2 signed status");
console.log("development only: in-memory reference stores");

const root: HybridKeyPairV2 = await generateHybridKeypair();
const agent: HybridKeyPairV2 = await generateHybridKeypair();
const status: HybridKeyPairV2 = await generateHybridKeypair();
const verifier: HybridKeyPairV2 = await generateHybridKeypair();
const rootID = keyIDV2(root.publicKey);
const agentID = keyIDV2(agent.publicKey);
const verifierID = keyIDV2(verifier.publicKey);

const cert = await signDelegationCertV2({
  version: 2, cert_id: certID,
  issuer_id: rootID, issuer_pub_key: root.publicKey, subject_id: agentID, subject_pub_key: agent.publicKey,
  scope: ["data:read"], constraints: [],
  issued_at: start, expires_at: start + 86400, signature: unsigned,
}, root);
console.log(`delegation: ${certID} scope=data:read`);

// The journal is the verifier's anchored record of key roles, status-key
// epochs and accepted status. Roles are recorded once, when the deployment
// authenticates its trust configuration.
const journal = new JournalStoreTestOnly();
await recordSecurityKeyRoleV2(journal, "issuer", root.publicKey);
await recordSecurityKeyRoleV2(journal, "delegation", agent.publicKey);
await recordSecurityKeyRoleV2(journal, "verifier", verifier.publicKey);
await configureStatusKeyEpochV2(journal, rootID, 1, status.publicKey);
console.log("journal: key roles recorded; status key configured for the root at epoch 1");

// Role separation: the root key can never sign status for itself.
const refused = await newV2StatusPublisherWithKey(journal, root.publicKey, root, 3600).then(() => null, (err: unknown) => err);
console.log(`publisher with the root key as status key: refused (${v2ErrorClassOf(refused)})`);

const publisher = await newV2StatusPublisherWithKey(journal, root.publicKey, status, 3600);
const policy: RevocationStatusPolicyV2 = { maxListLifetimeSeconds: 3600, maxStatusAgeSeconds: 3600, clockSkewSeconds: 5 };

// Genesis: sequence 1, nothing revoked. The caller persists the returned
// state before publishing the signed list.
const genesis = await publisher.genesis(start);
const genesisWire = encodeRevocationListV2(genesis.list);
console.log(`publisher: genesis list sequence ${genesis.list.sequence}`);
await applyRevocationListToJournalV2(journal, genesis.list, rootID, 1, status.publicKey, policy, start);
let certStatus = await revocationStatusFromJournalV2(journal, rootID, certID, 1, status.publicKey, policy, start);
console.log(`journal: ingested list sequence ${genesis.list.sequence}; ${certID} is ${certStatus.status}`);

const store = new StoreTestOnly(start, 30, logID, verifier);
const issuance = new ChallengeIssuanceStoreTestOnly();
let evidence: V2StatusEvidenceObject[] = [{ objectType: 3, wire: genesisWire }];

// verifyAndRelease runs one complete live verification at the store's
// current time and prints the released decision.
async function verifyAndRelease(label: string): Promise<void> {
  const challenge = await issueChallengeV2({ clock: store, store: issuance }, {
    verifierNamespace: namespace, replayEpoch: epoch, verifierID,
    lifetimeSeconds: 120, expectedAgentID: agentID, expectedAgentPublicKey: agent.publicKey,
  });
  const bundle = await signProofBundleV2({
    version: 2, verifier_id: verifierID, agent_id: agentID, agent_pub_key: agent.publicKey,
    delegations: [cert], delegation_digest: new Uint8Array(0),
    challenge: challenge.value, challenge_at: challenge.issuedAt, challenge_sig: unsigned,
    session_context: null, stream_id: null, stream_seq: null,
  }, agent);
  const expected = await loadExpectedChallengeV2(issuance, namespace, epoch, bundle.challenge);
  const outcome = await verifyProofBundleV2({
    bundle: encodeProofBundleV2(bundle), expected,
    contextPolicy: newV2ContextPolicy("example.signed-status/v1", false, null, null), requiredScope: "data:read",
    verifierNamespace: namespace, replayEpoch: epoch, verifierID, now: store.now(),
    maxChallengeAgeSeconds: 300, futureSkewSeconds: 5, tzdbVersion: TZDB_VERSION_V2,
    statusKeys: new Map([[rootID, { epoch: 1, key: status.publicKey }]]),
    statusPolicy: policy,
  }, {
    claimStore: store,
    trust: (chain) => chain[chain.length - 1]!.issuer_id === rootID
      ? { outcome: "trusted", rootKey: root.publicKey }
      : { outcome: "untrusted" },
    // The provider returns signed objects only; the verifier checks each
    // signature against the configured status key and applies it to the
    // journal before it derives a status.
    statusEvidence: async () => ({ objects: evidence }),
    statusJournal: journal,
  });
  if (outcome.stage !== "committed" || !outcome.committed) throw new Error(`verify stopped at ${outcome.stage}: ${outcome.error}`);
  const receiptWire = await store.publishV2Receipt(outcome.committed.claimID(), outcome.committed.receiptBody());
  const result = await releaseV2Decision(outcome.committed, receiptWire, {
    verifierPublicKey: verifier.publicKey, logID, claimStore: store, checkpoint: store,
  });
  if (result.status !== "released" || !result.decision) throw new Error(`release ${result.status}: ${result.reason}`);
  const receipt = result.decision.receipt();
  console.log(`${label}: decision=${result.decision.decision()} reason=${result.decision.reason()} ` +
    `status_assessment=${receipt.status_assessment} allowed=${await result.decision.allowed(store)}`);
}

store.setTime(start + 5);
await verifyAndRelease("verify before revocation");

// Revoke: a push with the newly revoked ID and the cumulative list, both at
// sequence 2.
const revoked = await publisher.revoke(genesis.state, [certID], start + 10);
const pushWire = encodeRevocationPushV2(revoked.push!);
const listWire = encodeRevocationListV2(revoked.list);
console.log(`publisher: revoked ${certID} (push sequence ${revoked.push!.sequence}, list sequence ${revoked.list.sequence})`);
await applyRevocationPushToJournalV2(journal, revoked.push!, rootID, 1, status.publicKey, policy, start + 10);
certStatus = await revocationStatusFromJournalV2(journal, rootID, certID, 1, status.publicKey, policy, start + 10);
console.log(`journal: ingested push sequence ${revoked.push!.sequence}; ${certID} is ${certStatus.status}`);

evidence = [{ objectType: 5, wire: pushWire }, { objectType: 3, wire: listWire }];
store.setTime(start + 15);
await verifyAndRelease("verify after revocation");
