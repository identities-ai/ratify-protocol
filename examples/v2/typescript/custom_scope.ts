// Ratify Protocol v2 custom scope and the standard max_count evaluator
// profile (com.ratifyprotocol.max_count/v1).
//
// DEVELOPMENT ONLY. This program uses the in-memory reference stores from
// @identities-ai/ratify-protocol/v2/reference. A production verifier supplies
// durable Part B stores and an independent checkpoint (SPEC-v2 §7).
//
// Run from this directory: node custom_scope.ts
import { generateHybridKeypair } from "@identities-ai/ratify-protocol";
import {
  CONSTRAINT_MAX_COUNT_V2,
  PROFILE_MAX_COUNT_V2,
  TZDB_VERSION_V2,
  configureStatusKeyEpochV2,
  constraintProfileDigestV2,
  encodeProofBundleV2,
  encodeRevocationListV2,
  issueChallengeV2,
  keyIDV2,
  loadExpectedChallengeV2,
  newConstraintEvaluatorRegistryV2,
  newV2ContextPolicy,
  newV2StatusPublisherWithKey,
  recordSecurityKeyRoleV2,
  releaseV2Decision,
  signDelegationCertV2,
  signProofBundleV2,
  standardMaxCountEvaluatorV2,
  v2ErrorClassOf,
  verifyProofBundleV2,
  type ConstraintEvaluatorRegistryV2,
  type DelegationCertV2,
  type HybridKeyPairV2,
} from "@identities-ai/ratify-protocol/v2";
import { ChallengeIssuanceStoreTestOnly, JournalStoreTestOnly, StoreTestOnly } from "@identities-ai/ratify-protocol/v2/reference";

const start = 1800000000;
const namespace = "custom-scope";
const epoch = 1;
const logID = "00000000000000000000000000000003";
const customScope = "custom:acme:deploy";
const unsigned = { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) }; // replaced when signed

console.log("Ratify Protocol v2 custom scope and max_count profile");
console.log("development only: in-memory reference stores");

const root: HybridKeyPairV2 = await generateHybridKeypair();
const agent: HybridKeyPairV2 = await generateHybridKeypair();
const status: HybridKeyPairV2 = await generateHybridKeypair();
const verifier: HybridKeyPairV2 = await generateHybridKeypair();
const rootID = keyIDV2(root.publicKey);
const agentID = keyIDV2(agent.publicKey);
const verifierID = keyIDV2(verifier.publicKey);

const template: DelegationCertV2 = {
  version: 2, cert_id: "custom-scope-cert-1",
  issuer_id: rootID, issuer_pub_key: root.publicKey, subject_id: agentID, subject_pub_key: agent.publicKey,
  scope: [], constraints: [],
  issued_at: start, expires_at: start + 86400, signature: unsigned,
};

// A custom scope is one exact name. Wildcards are invalid.
const refused = await signDelegationCertV2({ ...template, scope: ["custom:*"] }, root).then(() => null, (err: unknown) => err);
console.log(`issue scope custom:*: refused (${v2ErrorClassOf(refused)})`);

// The certificate carries an extension constraint. Only a verifier that
// registered the max_count/v1 profile for this type can evaluate it.
const cert = await signDelegationCertV2({
  ...template,
  scope: [customScope],
  constraints: [{ type: CONSTRAINT_MAX_COUNT_V2, params: { counter: "nodes", max: 5 } }],
}, root);
console.log(`delegation: scope=${customScope} constraint=${CONSTRAINT_MAX_COUNT_V2}(counter=nodes, max=5)`);

const maxCount = standardMaxCountEvaluatorV2();
console.log(`profile: ${PROFILE_MAX_COUNT_V2} digest=${constraintProfileDigestV2(maxCount.descriptor)}`);
const registry = newConstraintEvaluatorRegistryV2(1000, maxCount);

const journal = new JournalStoreTestOnly();
await recordSecurityKeyRoleV2(journal, "issuer", root.publicKey);
await configureStatusKeyEpochV2(journal, rootID, 1, status.publicKey);
const publisher = await newV2StatusPublisherWithKey(journal, root.publicKey, status, 3600);
const genesis = await publisher.genesis(start);
const statusWire = encodeRevocationListV2(genesis.list);

const store = new StoreTestOnly(start, 30, logID, verifier);
const issuance = new ChallengeIssuanceStoreTestOnly();

// attempt verifies one request for `nodes` nodes and releases the result.
async function attempt(label: string, nodes: number, evaluators: ConstraintEvaluatorRegistryV2 | null): Promise<void> {
  store.setTime(store.now() + 1);
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
    contextPolicy: newV2ContextPolicy("example.custom-scope/v1", false, null, null), requiredScope: customScope,
    verifierNamespace: namespace, replayEpoch: epoch, verifierID, now: store.now(),
    maxChallengeAgeSeconds: 300, futureSkewSeconds: 5, tzdbVersion: TZDB_VERSION_V2,
    // The requested quantity comes from the authenticated request, never
    // from the proof.
    context: { extensionCounts: new Map([["nodes", nodes]]) },
    constraintEvaluators: evaluators,
    statusKeys: new Map([[rootID, { epoch: 1, key: status.publicKey }]]),
    statusPolicy: { maxListLifetimeSeconds: 3600, maxStatusAgeSeconds: 3600, clockSkewSeconds: 5 },
  }, {
    claimStore: store,
    trust: (chain) => chain[chain.length - 1]!.issuer_id === rootID
      ? { outcome: "trusted", rootKey: root.publicKey }
      : { outcome: "untrusted" },
    statusEvidence: async () => ({ objects: [{ objectType: 3, wire: statusWire }] }),
    statusJournal: journal,
  });
  if (outcome.stage !== "committed" || !outcome.committed) throw new Error(`verify stopped at ${outcome.stage}: ${outcome.error}`);
  const receiptWire = await store.publishV2Receipt(outcome.committed.claimID(), outcome.committed.receiptBody());
  const result = await releaseV2Decision(outcome.committed, receiptWire, {
    verifierPublicKey: verifier.publicKey, logID, claimStore: store, checkpoint: store,
  });
  if (result.status !== "released" || !result.decision) throw new Error(`release ${result.status}: ${result.reason}`);
  const receipt = result.decision.receipt();
  console.log(`${label}: decision=${result.decision.decision()} reason=${result.decision.reason()} allowed=${await result.decision.allowed(store)}`);
  for (const ref of receipt.constraint_evaluators ?? []) {
    console.log(`  receipt constraint_evaluators: ${ref.type} ${ref.profile_digest}`);
  }
}

await attempt("request nodes=3", 3, registry);
await attempt("request nodes=8", 8, registry);
await attempt("request nodes=3 without the profile registered", 3, null);
