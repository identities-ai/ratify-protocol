import Foundation

public struct ConstraintProfileDescriptor: Sendable {
    public let profile: String
    public let type: String
    public init(profile: String, type: String) {
        self.profile = profile
        self.type = type
    }
}

public enum ConstraintOutcome: String, Sendable {
    case pass, denied, unverifiable, invalid
}

/// Verifier-authenticated values read by built-in and extension constraints.
public struct ConstraintContext: Sendable {
    public var requestedAmountMicros: Int64
    public var requestedCurrency: String
    public var hasAmount: Bool
    public var requestedResourceId: String
    public var requestedPath: String
    public var hasResource: Bool
    public var extensionCounts: [String: Int64]
    public var extensionValues: [String: String]

    public init(requestedAmountMicros: Int64 = 0, requestedCurrency: String = "", hasAmount: Bool = false,
                requestedResourceId: String = "", requestedPath: String = "", hasResource: Bool = false,
                extensionCounts: [String: Int64] = [:], extensionValues: [String: String] = [:]) {
        self.requestedAmountMicros = requestedAmountMicros
        self.requestedCurrency = requestedCurrency
        self.hasAmount = hasAmount
        self.requestedResourceId = requestedResourceId
        self.requestedPath = requestedPath
        self.hasResource = hasResource
        self.extensionCounts = extensionCounts
        self.extensionValues = extensionValues
    }

    var ffi: FfiConstraintContext {
        FfiConstraintContext(requestedAmountMicros: requestedAmountMicros, requestedCurrency: requestedCurrency,
            hasAmount: hasAmount, requestedResourceId: requestedResourceId, requestedPath: requestedPath,
            hasResource: hasResource, extensionCounts: extensionCounts, extensionValues: extensionValues)
    }

    init(_ f: FfiConstraintContext) {
        self.init(requestedAmountMicros: f.requestedAmountMicros, requestedCurrency: f.requestedCurrency,
            hasAmount: f.hasAmount, requestedResourceId: f.requestedResourceId,
            requestedPath: f.requestedPath, hasResource: f.hasResource,
            extensionCounts: f.extensionCounts, extensionValues: f.extensionValues)
    }
}

/// Complete input passed to a standard profile or registered evaluator.
public struct ConstraintEvaluationInput: Sendable {
    public let type: String
    public let paramsJSON: Data?
    public let delegationIndex: UInt64
    public let constraintIndex: UInt64
    public let issuerId: String
    public let certId: String
    public let context: ConstraintContext
    public let evaluationTime: Int64

    public init(type: String, paramsJSON: Data? = nil, delegationIndex: UInt64 = 0,
                constraintIndex: UInt64 = 0, issuerId: String = "", certId: String = "",
                context: ConstraintContext = ConstraintContext(), evaluationTime: Int64 = 0) {
        self.type = type
        self.paramsJSON = paramsJSON
        self.delegationIndex = delegationIndex
        self.constraintIndex = constraintIndex
        self.issuerId = issuerId
        self.certId = certId
        self.context = context
        self.evaluationTime = evaluationTime
    }

    var ffi: FfiConstraintEvaluationInput {
        FfiConstraintEvaluationInput(kind: type, paramsJson: paramsJSON, delegationIndex: delegationIndex,
            constraintIndex: constraintIndex, issuerId: issuerId, certId: certId, context: context.ffi,
            evaluationTime: evaluationTime)
    }

    init(_ f: FfiConstraintEvaluationInput) {
        self.init(type: f.kind, paramsJSON: f.paramsJson, delegationIndex: f.delegationIndex,
            constraintIndex: f.constraintIndex, issuerId: f.issuerId, certId: f.certId,
            context: ConstraintContext(f.context), evaluationTime: f.evaluationTime)
    }
}

public struct ConstraintEvaluationResult: Sendable {
    public let outcome: ConstraintOutcome
    public let validUntil: Int64
    public let detail: String

    public init(outcome: ConstraintOutcome, validUntil: Int64 = 0, detail: String = "") {
        self.outcome = outcome; self.validUntil = validUntil; self.detail = detail
    }

    init(_ result: FfiConstraintEvaluationResult) {
        outcome = ConstraintOutcome(rawValue: result.outcome)!
        validUntil = result.validUntil
        detail = result.detail
    }

    var ffi: FfiConstraintEvaluationResult {
        FfiConstraintEvaluationResult(outcome: outcome.rawValue, validUntil: validUntil, detail: detail)
    }
}

/// A pure extension evaluator. A callback that never returns delays verification.
public protocol ConstraintEvaluator: Sendable {
    func evaluate(_ input: ConstraintEvaluationInput) async throws -> ConstraintEvaluationResult
}

public struct ConstraintEvaluatorRegistration: Sendable {
    public let descriptor: ConstraintProfileDescriptor
    public let evaluator: any ConstraintEvaluator
    public init(descriptor: ConstraintProfileDescriptor, evaluator: any ConstraintEvaluator) {
        self.descriptor = descriptor; self.evaluator = evaluator
    }
}

final class ConstraintEvaluatorBridge: FfiConstraintEvaluator, @unchecked Sendable {
    private let evaluator: any ConstraintEvaluator
    init(_ evaluator: any ConstraintEvaluator) { self.evaluator = evaluator }
    func evaluate(input: FfiConstraintEvaluationInput, context: FfiStoreContext) throws -> FfiConstraintEvaluationResult {
        do { return try callbackWait(context: context) { try await self.evaluator.evaluate(ConstraintEvaluationInput(input)).ffi } }
        catch { throw FfiEvaluatorError.Failed(detail: "\(error)") }
    }
}

/// Immutable, caller-authenticated extension profiles validated by the core.
public final class ConstraintEvaluatorRegistry: @unchecked Sendable {
    let handle: FfiConstraintEvaluatorRegistry
    public let timeoutMilliseconds: UInt64
    public init(timeoutMilliseconds: UInt64, registrations: [ConstraintEvaluatorRegistration]) throws(RatifyError) {
        handle = try ffi { try FfiConstraintEvaluatorRegistry(timeoutMillis: timeoutMilliseconds,
            registrations: registrations.map { FfiConstraintEvaluatorRegistration(profile: $0.descriptor.profile,
                kind: $0.descriptor.type, evaluator: ConstraintEvaluatorBridge($0.evaluator)) }) }
        self.timeoutMilliseconds = timeoutMilliseconds
    }
    public func refs() throws(RatifyError) -> [ConstraintEvaluatorRef] {
        try ffi { try handle.refs().map(ConstraintEvaluatorRef.init) }
    }
}

extension Ratify {
    public static func validateRequestContext(_ context: ConstraintContext) throws(RatifyError) {
        try ffi { try ffiValidateRequestContext(context: context.ffi) }
    }

    public static func constraintProfileDigest(_ descriptor: ConstraintProfileDescriptor) throws(RatifyError) -> String {
        try ffi { try ffiConstraintProfileDigest(profile: descriptor.profile, kind: descriptor.type) }
    }

    public static func evaluateMaxCount(_ input: ConstraintEvaluationInput) throws(RatifyError) -> ConstraintEvaluationResult {
        ConstraintEvaluationResult(try ffi { try ffiEvaluateMaxCount(input: input.ffi) })
    }

    public static func evaluateAllowedValues(_ input: ConstraintEvaluationInput) throws(RatifyError) -> ConstraintEvaluationResult {
        ConstraintEvaluationResult(try ffi { try ffiEvaluateAllowedValues(input: input.ffi) })
    }
}
