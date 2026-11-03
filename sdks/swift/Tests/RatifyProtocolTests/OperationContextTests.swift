import Foundation
import XCTest
import RatifyProtocol

/// Negative field checks ported from the Rust operation-context tests.
final class OperationContextTests: XCTestCase {
    typealias R = OperationContextRunner

    func testContextFieldValidation() throws {
        let f = Corpus.load("operation-session-context.json")
        var op = R.operation(f.obj("operation_input"))
        op.payloadDigest.removeLast()
        XCTAssertNotEqual(classOf { _ = try Ratify.operationContextHash(op) }, "ok")
        let input = f.obj("input")
        var s = R.session(input, Data(count: 32))
        XCTAssertNoThrow(try Ratify.sessionContextBytes(s))
        s.verifierId = s.verifierId.uppercased()
        XCTAssertEqual(classOf { _ = try Ratify.sessionContextBytes(s) }, "configuration_invalid")
        s = R.session(input, Data(count: 31))
        XCTAssertEqual(classOf { _ = try Ratify.sessionContextBytes(s) }, "configuration_invalid")
        s = R.session(input, Data(count: 32))
        s.workspaceId = "00000000-0000-4000-8000-00000000000A"
        XCTAssertEqual(classOf { _ = try Ratify.sessionContextBytes(s) }, "configuration_invalid")
        s = R.session(input, Data(count: 32))
        s.verifierId = String(s.verifierId.prefix(32))
        XCTAssertEqual(classOf { _ = try Ratify.sessionContextBytes(s) }, "configuration_invalid")
        s = R.session(input, Data(count: 32))
        s.agentId = "not-a-key-id"
        XCTAssertEqual(classOf { _ = try Ratify.sessionContextBytes(s) }, "configuration_invalid")
        s = R.session(input, Data(count: 32))
        s.agentId = String(s.agentId.prefix(32))
        XCTAssertEqual(classOf { _ = try Ratify.sessionContextBytes(s) }, "configuration_invalid")
    }

    /// Length prefixes keep field boundaries from colliding.
    func testLengthPrefixesPreventBoundaryCollisions() throws {
        let left = OperationContext(requiredScope: "data:read", operation: "records.get",
                                    resourceId: "r1", requestedPath: "/records/1")
        var right = left
        right.resourceId = "r1/records"
        right.requestedPath = "/1"
        XCTAssertNotEqual(try Ratify.operationContextHash(left), try Ratify.operationContextHash(right))
    }
}
