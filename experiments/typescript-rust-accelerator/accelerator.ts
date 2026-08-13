import type { ProofBundle, VerifyOptions, VerifyResult } from "../../sdks/typescript/src/types.js";
import { base64StandardEncode } from "../../sdks/typescript/src/canonical.js";
import { encodeProofBundle } from "../../sdks/typescript/src/wire.js";
import { verifyBundle as typescriptVerifyBundle } from "../../sdks/typescript/src/verify.js";

export interface NativeVerifier {
  verifyBundleJson(bundle: string, options: string): string;
  verifyBundleJsonAsync?(bundle: string, options: string): Promise<string>;
}

export function nativeEligible(options: VerifyOptions): boolean {
  return !(
    options.is_revoked || options.revocation || options.force_revocation_check ||
    options.policy || options.audit || options.constraint_evaluators ||
    options.policy_verdict || options.policy_secret || options.anchor_resolver ||
    options.challenge_store || options.context?.invocations_in_window
  );
}

function base64(value?: Uint8Array): string {
  return value?.length ? base64StandardEncode(value) : "";
}

function nativeOptions(options: VerifyOptions): string {
  const context = options.context;
  return JSON.stringify({
    required_scope: options.required_scope ?? "",
    now: options.now,
    session_context: base64(options.session_context),
    stream: options.stream ? {
      stream_id: base64(options.stream.stream_id),
      last_seen_seq: options.stream.last_seen_seq,
    } : undefined,
    context: context ? {
      current_lat: context.current_lat,
      current_lon: context.current_lon,
      current_alt_m: context.current_alt_m,
      current_speed_mps: context.current_speed_mps,
      requested_amount: context.requested_amount,
      requested_currency: context.requested_currency,
      requested_resource_id: context.requested_resource_id,
      requested_path: context.requested_path,
    } : {},
  });
}

export async function verifyBundle(
  bundle: ProofBundle,
  options: VerifyOptions,
  native: NativeVerifier | undefined,
): Promise<VerifyResult> {
  if (!native || !nativeEligible(options)) return typescriptVerifyBundle(bundle, options);
  try {
    const encoded = encodeProofBundle(bundle);
    const result = native.verifyBundleJsonAsync
      ? await native.verifyBundleJsonAsync(encoded, nativeOptions(options))
      : native.verifyBundleJson(encoded, nativeOptions(options));
    return JSON.parse(result);
  } catch {
    return typescriptVerifyBundle(bundle, options);
  }
}
