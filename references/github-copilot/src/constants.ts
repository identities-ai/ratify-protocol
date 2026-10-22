export const REQUIRED_SCOPE = "custom:github:deploy";
export const REPOSITORY = "identities-ai/copilot-authority-demo";
// Git resource-identifier profile (docs/RESOURCE_PROFILES.md), carried as the
// opaque resource_id of a Protocol v2 resource_path constraint.
export const RESOURCE_ID = `git:github.com/${REPOSITORY}`;
export const ALLOWED_PATH = "/services/payments/environments/staging";
// v2 session context requires a canonical lowercase UUID workspace ID.
export const WORKSPACE_ID = "6f1c2a52-8d0e-4b7a-9c35-2f4e8b1d7a90";
export const SESSION_ID = "copilot-demo-session";
export const CERT_ID = "ratify-copilot-reference-cert";
export const OPERATION = "github.deploy";
export const VERIFIER_NAMESPACE = "ratify-copilot-reference";
export const REPLAY_EPOCH = 1;
export const LOG_ID = "0000000000000000000000000000c0b1";
export const CONTEXT_PROFILE = "ratify.reference.github-copilot.session-context/v1";
export const CONTEXT_FIELDS = ["verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"] as const;
