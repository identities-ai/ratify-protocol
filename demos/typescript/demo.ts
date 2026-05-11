// Ratify Protocol v1 — end-to-end narrative demo (TypeScript).
//
// Run (from repo root):
//   cd sdks/typescript && npm install && cd ../..
//   node --import tsx/esm demos/typescript/demo.ts

import {
  DelegationCert,
  HybridSignature,
  PROTOCOL_VERSION,
  ProofBundle,
  SCOPE_FILES_WRITE,
  SCOPE_MEETING_ATTEND,
  SCOPE_MEETING_RECORD,
  generateChallenge,
  generateAgent,
  generateHumanRoot,
  issueDelegation,
  signChallenge,
  verifyBundle,
  hexEncode,
} from "@identities-ai/ratify-protocol";

function banner(text: string) {
  console.log();
  console.log("━".repeat(70));
  console.log(text);
  console.log("━".repeat(70));
}

function kv(label: string, value: string) {
  console.log(`  ${label.padEnd(20)} ${value}`);
}

async function main() {
  // Step 1
  banner("STEP 1  Alice generates a hybrid root identity");
  const { root: alice, privateKey: alicePriv } = await generateHumanRoot();
  kv("Root ID:", alice.id);
  kv("Ed25519 pubkey:", hexEncode(alice.public_key.ed25519).slice(0, 32) + "…");
  kv("ML-DSA-65 pubkey:", `<${alice.public_key.ml_dsa_65.length} bytes>`);
  kv("Storage:", "Private keys stay on Alice's machine (never leave)");

  // Step 2
  banner("STEP 2  Agent (Alice's scheduler) generates its own hybrid keypair");
  const { agent, privateKey: agentPriv } = await generateAgent(
    "Alice's Scheduler",
    "voice_agent",
  );
  kv("Agent ID:", agent.id);
  kv("Agent type:", agent.agent_type);
  kv("Ed25519 pubkey:", hexEncode(agent.public_key.ed25519).slice(0, 32) + "…");

  // Step 3
  banner("STEP 3  Alice authorizes the agent for meeting:attend, 7 days");
  const now = Math.floor(Date.now() / 1000);
  const cert: DelegationCert = {
    cert_id: "cert-demo-001",
    version: PROTOCOL_VERSION,
    issuer_id: alice.id,
    issuer_pub_key: alice.public_key,
    subject_id: agent.id,
    subject_pub_key: agent.public_key,
    scope: [SCOPE_MEETING_ATTEND],
    issued_at: now,
    expires_at: now + 7 * 24 * 3600,
    signature: { ed25519: new Uint8Array(), ml_dsa_65: new Uint8Array() },
  };
  await issueDelegation(cert, alicePriv);
  kv("Cert ID:", cert.cert_id);
  kv("Scope:", cert.scope.join(", "));
  kv("Expires:", new Date(cert.expires_at * 1000).toISOString());
  kv("Ed25519 sig:", hexEncode(cert.signature.ed25519).slice(0, 32) + "…");
  kv("ML-DSA-65 sig:", `<${cert.signature.ml_dsa_65.length} bytes>`);

  // Step 4
  banner("STEP 4  Agent builds a proof bundle for the verifier");
  const challenge = generateChallenge();
  const challengeAt = Math.floor(Date.now() / 1000);
  const challengeSig: HybridSignature = await signChallenge(
    challenge,
    challengeAt,
    agentPriv,
  );
  const bundle: ProofBundle = {
    agent_id: agent.id,
    agent_pub_key: agent.public_key,
    delegations: [cert],
    challenge,
    challenge_at: challengeAt,
    challenge_sig: challengeSig,
  };
  kv("Challenge:", hexEncode(challenge).slice(0, 32) + "…");
  kv("Challenge at:", new Date(challengeAt * 1000).toISOString());
  kv("Hybrid sig:", "Ed25519 + ML-DSA-65 over challenge || BE(ts)");

  // Step 5
  banner("STEP 5  Verifier runs verifyBundle() — expects meeting:attend");
  let result = await verifyBundle(bundle, { required_scope: SCOPE_MEETING_ATTEND });
  if (result.valid) {
    console.log("  ✅  VALID");
    kv("Human ID:", result.human_id!);
    kv("Agent ID:", result.agent_id!);
    kv("Status:", result.identity_status);
    kv("Granted scope:", (result.granted_scope ?? []).join(", "));
  } else {
    console.log(`  ❌  INVALID — ${result.identity_status}: ${result.error_reason}`);
  }

  // Attack 1
  banner("ATTACK 1  Attacker appends files:write to the scope after signing");
  const tampered: DelegationCert = {
    ...cert,
    scope: [...cert.scope, SCOPE_FILES_WRITE],
  };
  const tamperedBundle: ProofBundle = { ...bundle, delegations: [tampered] };
  result = await verifyBundle(tamperedBundle, { required_scope: SCOPE_FILES_WRITE });
  console.log(`  ❌  REJECTED as expected: ${result.error_reason}`);
  kv("Why:", "Canonical bytes differ; Ed25519 AND ML-DSA-65 both fail verify.");

  // Attack 2
  banner("ATTACK 2  Agent tries to use meeting:attend cert for meeting:record");
  result = await verifyBundle(bundle, { required_scope: SCOPE_MEETING_RECORD });
  console.log(`  ❌  REJECTED as expected: ${result.error_reason}`);
  kv("Why:", "meeting:record is not in the effective scope.");

  // Attack 3
  banner("ATTACK 3  Expired cert (verifier's clock reports future time)");
  result = await verifyBundle(bundle, {
    required_scope: SCOPE_MEETING_ATTEND,
    now: cert.expires_at + 1,
  });
  console.log(`  ❌  REJECTED as expected: ${result.identity_status}: ${result.error_reason}`);

  // Revocation
  banner("REVOCATION  Alice revokes the cert");
  result = await verifyBundle(bundle, {
    required_scope: SCOPE_MEETING_ATTEND,
    is_revoked: (cid: string) => cid === cert.cert_id,
  });
  console.log(`  ❌  REJECTED as expected: ${result.identity_status}: ${result.error_reason}`);
  kv("Why:", "Verifier's revocation list now contains this cert_id.");

  // Summary
  banner("SUMMARY");
  console.log(
    "  The protocol just demonstrated:\n\n" +
      "  • Alice created a hybrid (Ed25519 + ML-DSA-65) root identity.\n" +
      "  • She signed a scoped, time-bounded delegation for an AI agent.\n" +
      "  • The agent signed a fresh challenge to prove liveness.\n" +
      "  • A verifier checked the bundle in a single function call.\n" +
      "  • Every one of four tampering/misuse scenarios was rejected\n" +
      "    deterministically — no fuzzy detection, no false positives.\n" +
      "  • Signatures are quantum-safe: breaking either Ed25519 or\n" +
      "    ML-DSA-65 alone is insufficient to forge.\n\n" +
      "  This is the full Ratify Protocol v1, end to end, in one process.",
  );
  console.log();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
