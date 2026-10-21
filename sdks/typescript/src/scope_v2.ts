// Protocol v2 scope rules (Go ValidateScopesV2, ValidateRequiredScopeV2,
// ExpandScopes, IntersectScopes). The v1 helpers in scope.ts stay unchanged.

import { CUSTOM_SCOPE_PREFIX, scopeWildcards, vocabulary } from "./scope.js";
import { compareStrings } from "./json_v2.js";

const VALID = new Set(vocabulary());
const WILDCARDS = new Map(Object.entries(scopeWildcards()));

export const SCOPE_IDENTITY_DELEGATE_V2 = "identity:delegate";

export function isWildcardScopeV2(scope: string): boolean {
  return WILDCARDS.has(scope);
}

function isValidScopeV2(s: string): boolean {
  return VALID.has(s) || WILDCARDS.has(s) || (s.startsWith(CUSTOM_SCOPE_PREFIX) && s.length > CUSTOM_SCOPE_PREFIX.length);
}

/** Go ValidateScopesV2. Returns an error message or null. */
export function validateScopesV2(scopes: readonly string[] | null): string | null {
  if (!scopes || scopes.length === 0) return "scope must be a non-empty array";
  for (const s of scopes) {
    if (!isValidScopeV2(s)) return `unknown scope ${JSON.stringify(s)}: not in canonical vocabulary and not a custom: extension`;
  }
  const seen = new Set<string>();
  for (const s of scopes) {
    if (s === "custom:*") return "custom:* is not a valid scope";
    if (seen.has(s)) return `duplicate scope ${JSON.stringify(s)}`;
    seen.add(s);
  }
  return null;
}

/** Go ValidateRequiredScopeV2: exactly one registered canonical scope. */
export function validateRequiredScopeV2(scope: string): string | null {
  if (typeof scope !== "string" || !VALID.has(scope) || WILDCARDS.has(scope) || scope.startsWith(CUSTOM_SCOPE_PREFIX)) {
    return "required scope must be one non-empty canonical scope";
  }
  return null;
}

export function expandScopesV2(scopes: readonly string[]): string[] {
  const seen = new Set<string>();
  for (const s of scopes) {
    const children = WILDCARDS.get(s);
    if (children) for (const c of children) seen.add(c);
    else seen.add(s);
  }
  return [...seen].sort(compareStrings);
}

export function intersectScopesV2(lists: readonly (readonly string[])[]): string[] {
  if (lists.length === 0) return [];
  let effective = new Set(expandScopesV2(lists[0]!));
  for (let i = 1; i < lists.length; i++) {
    const next = new Set(expandScopesV2(lists[i]!));
    effective = new Set([...effective].filter((s) => next.has(s)));
  }
  return [...effective].sort(compareStrings);
}
