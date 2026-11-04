import Foundation
import RatifyProtocol

enum EvaluatorRunner {
    static func context(_ json: [String: Any]) -> ConstraintContext {
        let counts = (json["extension_counts"] as? [String: NSNumber] ?? [:]).mapValues(\.int64Value)
        let values = json["extension_values"] as? [String: String] ?? [:]
        return ConstraintContext(extensionCounts: counts, extensionValues: values)
    }

    static func run() async throws {
        let corpus = Corpus.load("evaluator-profiles.json")
        let tally = Tally("evaluator-profiles.json")
        for profile in corpus.arr("profiles") {
            let kind = profile.s("type")
            let digest = try Ratify.constraintProfileDigest(ConstraintProfileDescriptor(profile: profile.s("profile"), type: kind))
            tally.check("profiles", kind, digest == profile.s("profile_digest"))
            for item in profile.arr("cases") {
                let params = item["params_absent"] as? Bool == true ? nil :
                    try JSONSerialization.data(withJSONObject: item["params"] ?? NSNull(), options: [.fragmentsAllowed, .sortedKeys])
                let input = ConstraintEvaluationInput(type: kind, paramsJSON: params,
                    context: context(item["context"] as? [String: Any] ?? [:]))
                let result = kind.hasSuffix("max_count") ? try Ratify.evaluateMaxCount(input) :
                    try Ratify.evaluateAllowedValues(input)
                tally.check("cases", "\(kind)/\(item.s("name"))", result.outcome.rawValue == item.s("outcome"), result.outcome.rawValue)
            }
        }
        for item in corpus.arr("context_bounds") {
            let outcome: ErrorClass?
            do {
                try Ratify.validateRequestContext(context(item.obj("context")))
                outcome = nil
            } catch {
                outcome = error.errorClass
            }
            tally.check("bounds", item.s("name"), outcome?.rawValue == item["error_class"] as? String)
        }
        tally.finish([("profiles", corpus.arr("profiles").count),
            ("cases", corpus.arr("profiles").reduce(0) { $0 + $1.arr("cases").count }),
            ("bounds", corpus.arr("context_bounds").count)])
    }
}
