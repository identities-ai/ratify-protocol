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
}

public struct ConstraintEvaluationResult: Sendable {
    public let outcome: ConstraintOutcome
    public let validUntil: Int64
    public let detail: String

    init(_ result: FfiConstraintEvaluationResult) {
        outcome = ConstraintOutcome(rawValue: result.outcome)!
        validUntil = result.validUntil
        detail = result.detail
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
