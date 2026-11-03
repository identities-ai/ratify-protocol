import Foundation
import RatifyProtocol

/// operation-session-context.json through the public API: operation and
/// session context digests, the context policy digest, and payload digests.
enum OperationContextRunner {
    static func operation(_ v: [String: Any]) -> OperationContext {
        OperationContext(requiredScope: v.s("required_scope"), operation: v.s("operation"),
                         resourceId: v.s("resource_id"), requestedPath: v.s("requested_path"),
                         payloadDigest: (v["payload_digest_hex"] as? String).map { Data(hex: $0) } ?? Data())
    }

    static func session(_ v: [String: Any], _ requestHash: Data) -> SessionContextInputs {
        SessionContextInputs(verifierId: v.s("verifier_id"), workspaceId: v.s("workspace_id"), agentId: v.s("agent_id"),
                             sessionId: v.s("session_id"), invocationId: v.s("invocation_id"), requestHash: requestHash)
    }

    static func run() throws {
        let f = Corpus.load("operation-session-context.json")
        let t = Tally("operation-session-context.json")

        let policy = f.obj("context_policy")
        let p = try ContextPolicy(profile: policy.s("profile"), requireBound: policy.bool("require_bound"),
                                  requiredFields: policy.strings("required_fields"),
                                  expectedSessionContext: f.hex("expected_session_context_hex"))
        t.check("context_policy", "digest", p.digest == f.s("context_policy_digest"), p.digest)

        let hash = try Ratify.operationContextHash(operation(f.obj("operation_input")))
        t.check("request_hash", "operation_input", hash.hex == f.s("expected_request_hash_hex"), hash.hex)
        let input = f.obj("input")
        let ctx = try Ratify.buildSessionContext(session(input, input.hex("request_hash_hex")))
        t.check("session_context", "input", ctx.hex == f.s("expected_session_context_hex"), ctx.hex)

        let empty = try Ratify.operationContextHash(operation(f.obj("empty_payload_operation_input")))
        t.check("request_hash", "empty_payload", empty.hex == f.s("expected_empty_request_hash_hex"), empty.hex)
        let emptyCtx = try Ratify.buildSessionContext(session(input, empty))
        t.check("session_context", "empty_payload", emptyCtx.hex == f.s("expected_empty_session_context_hex"), emptyCtx.hex)

        let base = operation(f.obj("operation_input"))
        let invalid = f.strings("invalid_required_scopes")
        for scope in invalid {
            var op = base
            op.requiredScope = scope
            t.check("invalid_required_scopes", scope, (try? Ratify.operationContextHash(op)) == nil, "accepted")
        }

        let cases = f.arr("verify_api_payload_digest_decode_cases")
        for c in cases {
            let result = Result { () throws(RatifyError) in try Ratify.decodePayloadDigest(c["encoded"] as? String) }
            var ok: Bool
            switch result {
            case let .success(decoded):
                ok = c.bool("valid") && (decoded?.hex ?? "") == c.s("expected_hex")
            case .failure:
                ok = !c.bool("valid")
            }
            t.check("payload_digest_decode", c.s("name"), ok, "\(result)")
        }

        let vin = f.obj("verify_api_operation_input")
        let digest = try Ratify.decodePayloadDigest(vin.s("payload_digest"))!
        let vctx = OperationContext(requiredScope: vin.s("required_scope"), operation: vin.s("operation"),
                                    resourceId: vin.s("resource_id"), requestedPath: vin.s("requested_path"),
                                    payloadDigest: digest)
        let vhash = try Ratify.operationContextHash(vctx)
        t.check("request_hash", "verify_api", vhash.hex == f.s("expected_verify_api_request_hash_hex")
                    && vhash == hash, vhash.hex)

        t.finish([
            ("context_policy", 1),
            ("request_hash", 3),
            ("session_context", 2),
            ("invalid_required_scopes", invalid.count),
            ("payload_digest_decode", cases.count),
        ])
    }
}
