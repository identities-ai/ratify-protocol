// Console client configuration of the Verify MCP signer (Preview).

import { base64DecodeCanonical, bytesEqual, isWellFormedString, parseJSONV2, utf8, type JNode } from "../json_v2.js";
import { decodeDelegationCertV2, type DelegationCertV2 } from "../protocol_v2_wire.js";
import { InvalidConfigError } from "./errors.js";

const ENDPOINT_PATTERN = /^https:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?$/;
/** @internal */
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** @internal */
export const HEX64_PATTERN = /^[0-9a-f]{64}$/;

/**
 * Preview. The configuration the console shows when an agent is connected:
 * the pinned endpoint and audience, the verifier and workspace, the
 * connection, and the delegation chain ending at the agent key.
 */
export interface ClientConfig {
  readonly endpoint: string;
  readonly audience: string;
  readonly verifierID: string;
  readonly workspaceID: string;
  readonly connectionID: string;
  /** The decoded certificates, root side first; the last one is issued to the agent key. */
  readonly delegations: readonly DelegationCertV2[];
}

/** @internal The endpoint grammar, and audience is the endpoint followed by "/mcp". */
export function validEndpoint(endpoint: string, audience: string): boolean {
  return ENDPOINT_PATTERN.test(endpoint) && audience === endpoint + "/mcp";
}

/**
 * @internal A JSON object (not an array or null) from valid UTF-8 bytes or
 * well-formed text, or null. JSON.parse accepts no NaN or Infinity.
 */
export function parseJSONObject(data: Uint8Array | string): Record<string, unknown> | null {
  let parsed: unknown;
  try {
    if (typeof data === "string") {
      if (!isWellFormedString(data)) return null;
      parsed = JSON.parse(data);
    } else {
      parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data));
    }
  } catch {
    return null;
  }
  return isObject(parsed) ? parsed : null;
}

const INTEGER_LEXEME = /^-?(0|[1-9][0-9]*)$/;

/**
 * @internal True when data is a JSON object whose named top-level members,
 * where present, are spelled as JSON integers -?(0|[1-9][0-9]*). JSON.parse
 * reads 1.0 and 1e3 as integers, so the spelling is checked on the source.
 */
export function integerLexemes(data: Uint8Array | string, names: readonly string[]): boolean {
  let root: JNode;
  try {
    root = parseJSONV2(typeof data === "string" ? utf8(data) : data);
  } catch {
    return false;
  }
  if (root.k !== "obj") return false;
  for (const name of names) {
    const node = root.m.get(name);
    if (node !== undefined && (node.k !== "num" || !INTEGER_LEXEME.test(node.raw))) return false;
  }
  return true;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** @internal Own property of a parsed JSON object, never one inherited from Object.prototype. */
export function field(obj: Record<string, unknown>, name: string): unknown {
  return Object.prototype.hasOwnProperty.call(obj, name) ? obj[name] : undefined;
}

/**
 * Preview. Parses the console's client configuration: either the
 * client_config object itself or a JSON object that carries it under
 * "client_config" (the console's connect response). Other fields are
 * ignored, so a signer configuration file that also holds a key reference
 * parses too.
 *
 *  - endpoint: "https://" and a lowercase host name with an optional port,
 *    nothing else (no path, query, fragment, credentials, or trailing slash)
 *  - audience: exactly endpoint + "/mcp"
 *  - verifier_id: 64 lowercase hex characters
 *  - workspace_id, connection_id: lowercase UUIDs
 *  - delegations: a non-empty array of canonical standard base64 strings,
 *    each a SPEC-v2 delegation certificate, root side first, each issued by
 *    the subject (ID and public key) of the one before it
 *
 * The input must be valid UTF-8 (or well-formed text). Throws InvalidConfigError.
 */
export function parseClientConfig(data: Uint8Array | string): ClientConfig {
  let top = parseJSONObject(data);
  if (top === null) throw new InvalidConfigError();
  const inner = field(top, "client_config");
  if (isObject(inner)) top = inner;
  const strings: string[] = [];
  for (const name of ["endpoint", "audience", "verifier_id", "workspace_id", "connection_id"]) {
    const v = field(top, name);
    if (typeof v !== "string") throw new InvalidConfigError();
    strings.push(v);
  }
  const [endpoint, audience, verifierID, workspaceID, connectionID] = strings as [string, string, string, string, string];
  if (!validEndpoint(endpoint, audience) || !HEX64_PATTERN.test(verifierID) ||
      !UUID_PATTERN.test(workspaceID) || !UUID_PATTERN.test(connectionID)) {
    throw new InvalidConfigError();
  }
  const items = field(top, "delegations");
  if (!Array.isArray(items) || items.length === 0) throw new InvalidConfigError();
  const delegations: DelegationCertV2[] = [];
  for (const item of items) {
    if (typeof item !== "string") throw new InvalidConfigError();
    const wire = base64DecodeCanonical(item);
    if (wire === null) throw new InvalidConfigError();
    try {
      delegations.push(decodeDelegationCertV2(wire));
    } catch {
      throw new InvalidConfigError();
    }
  }
  // Root side first: each certificate is issued by the subject of the one before it.
  for (let i = 0; i + 1 < delegations.length; i++) {
    const parent = delegations[i]!;
    const child = delegations[i + 1]!;
    if (parent.subject_id !== child.issuer_id || !bytesEqual(parent.subject_pub_key.ed25519, child.issuer_pub_key.ed25519) ||
        !bytesEqual(parent.subject_pub_key.ml_dsa_65, child.issuer_pub_key.ml_dsa_65)) {
      throw new InvalidConfigError();
    }
  }
  return Object.freeze({ endpoint, audience, verifierID, workspaceID, connectionID, delegations: Object.freeze(delegations) });
}
