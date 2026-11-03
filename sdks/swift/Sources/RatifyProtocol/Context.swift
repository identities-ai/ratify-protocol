import Foundation

/// The operation a presentation authorizes (SPEC-v2 operation context).
public struct OperationContext: Sendable, Hashable {
    public var requiredScope: String
    public var operation: String
    public var resourceId: String
    public var requestedPath: String
    /// Empty, or exactly 32 raw SHA-256 bytes.
    public var payloadDigest: Data

    public init(requiredScope: String, operation: String, resourceId: String,
                requestedPath: String, payloadDigest: Data = Data()) {
        self.requiredScope = requiredScope
        self.operation = operation
        self.resourceId = resourceId
        self.requestedPath = requestedPath
        self.payloadDigest = payloadDigest
    }

    var ffi: FfiOperationContext {
        FfiOperationContext(requiredScope: requiredScope, operation: operation, resourceId: resourceId,
                            requestedPath: requestedPath, payloadDigest: payloadDigest)
    }
}

/// Verifier session and invocation inputs bound to a presentation.
public struct SessionContextInputs: Sendable, Hashable {
    public var verifierId: String
    public var workspaceId: String
    public var agentId: String
    public var sessionId: String
    public var invocationId: String
    /// Exactly 32 raw bytes from `Ratify.operationContextHash`.
    public var requestHash: Data

    public init(verifierId: String, workspaceId: String, agentId: String,
                sessionId: String, invocationId: String, requestHash: Data) {
        self.verifierId = verifierId
        self.workspaceId = workspaceId
        self.agentId = agentId
        self.sessionId = sessionId
        self.invocationId = invocationId
        self.requestHash = requestHash
    }

    var ffi: FfiSessionContextInputs {
        FfiSessionContextInputs(verifierId: verifierId, workspaceId: workspaceId, agentId: agentId,
                                sessionId: sessionId, invocationId: invocationId, requestHash: requestHash)
    }
}

extension Ratify {
    public static func operationContextHash(_ context: OperationContext) throws(RatifyError) -> Data {
        try ffi { try ffiOperationContextHash(context: context.ffi) }
    }

    public static func sessionContextBytes(_ inputs: SessionContextInputs) throws(RatifyError) -> Data {
        try ffi { try ffiSessionContextBytes(inputs: inputs.ffi) }
    }

    public static func buildSessionContext(_ inputs: SessionContextInputs) throws(RatifyError) -> Data {
        try ffi { try ffiBuildSessionContext(inputs: inputs.ffi) }
    }

    /// Decode `sha256:<64 lowercase hex>` into 32 raw bytes; nil in, nil out.
    public static func decodePayloadDigest(_ encoded: String?) throws(RatifyError) -> Data? {
        try ffi { try ffiDecodePayloadDigest(encoded: encoded) }
    }
}

/// A validated, fingerprinted context policy.
public final class ContextPolicy: Sendable {
    let handle: FfiContextPolicy

    public init(profile: String, requireBound: Bool, requiredFields: [String],
                expectedSessionContext: Data = Data()) throws(RatifyError) {
        handle = try ffi {
            try FfiContextPolicy(profile: profile, requireBound: requireBound,
                                 requiredFields: requiredFields, expectedSessionContext: expectedSessionContext)
        }
    }

    /// `sha384:` + 96 lowercase hex characters.
    public var digest: String { handle.digest() }
    public var profile: String { handle.profile() }
    public var requireBound: Bool { handle.requireBound() }
    public var requiredFields: [String] { handle.requiredFields() }
    public var expectedSessionContext: Data { handle.expectedSessionContext() }
}
