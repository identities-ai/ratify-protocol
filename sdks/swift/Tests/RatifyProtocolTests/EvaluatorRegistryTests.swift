import XCTest
import RatifyProtocol

final class EvaluatorRegistryTests: XCTestCase {
    struct PassingEvaluator: ConstraintEvaluator {
        func evaluate(_ input: ConstraintEvaluationInput) -> ConstraintEvaluationResult {
            ConstraintEvaluationResult(outcome: .pass)
        }
    }

    func testRegistryValidatesAndFreezesProfiles() throws {
        let entry = ConstraintEvaluatorRegistration(
            descriptor: ConstraintProfileDescriptor(profile: "com.example.limit/v1", type: "com.example.limit"),
            evaluator: PassingEvaluator())
        let registry = try ConstraintEvaluatorRegistry(timeoutMilliseconds: 100, registrations: [entry])
        XCTAssertEqual(registry.timeoutMilliseconds, 100)
        XCTAssertEqual(try registry.refs().map(\.kind), ["com.example.limit"])
        XCTAssertEqual(try registry.refs().first?.profileDigest,
            try Ratify.constraintProfileDigest(entry.descriptor))
        XCTAssertThrowsError(try ConstraintEvaluatorRegistry(timeoutMilliseconds: 0, registrations: [entry]))
        XCTAssertThrowsError(try ConstraintEvaluatorRegistry(timeoutMilliseconds: 100, registrations: [entry, entry]))
    }
}
