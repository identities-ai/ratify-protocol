import Foundation
import XCTest
@testable import RatifyProtocol

/// Arms the one-shot panic injection point of a `test-hooks` build. A build
/// without the hook fails to link this suite, so the tests can never be
/// silently skipped.
@_silgen_name("ratify_ffi_test_arm_panic")
private func armPanic()

/// A Rust panic surfaces as `RatifyError.internal(.panic)` through public
/// calls that were formerly non-throwing and through throwing ones, and a
/// panic inside a handle's method poisons only that handle.
final class PanicTests: XCTestCase {
    func testPanicInAQueryIsInternal() {
        armPanic()
        XCTAssertEqual(internalKind { _ = try Ratify.validId(String(repeating: "a", count: 64)) }, .panic)
        XCTAssertTrue(try Ratify.validId(String(repeating: "a", count: 64)), "the next call is unaffected")
    }

    func testPanicInADecoderIsInternal() {
        armPanic()
        XCTAssertEqual(internalKind { _ = try Ratify.decodeProofBundle(Data("{}".utf8)) }, .panic)
        XCTAssertEqual(classOf { _ = try Ratify.decodeProofBundle(Data("{}".utf8)) }, "malformed")
    }

    func testPanicInAMethodPoisonsOnlyThatHandle() throws {
        let key = try SoftwarePrivateKey.generate()
        let other = try SoftwarePrivateKey.generate()
        armPanic()
        XCTAssertEqual(internalKind { _ = try ffi { try key.handle.keyId() } }, .panic)
        XCTAssertEqual(internalKind { _ = try ffi { try key.handle.keyId() } }, .poisoned)
        XCTAssertEqual(try ffi { try other.handle.keyId() }, other.keyId)
    }

    func testInternalKindsPinned() {
        XCTAssertEqual(Set(InternalErrorKind.allCases.map(\.rawValue)), ["panic", "poisoned", "random_source"])
    }

    private func internalKind(_ body: () throws -> Void) -> InternalErrorKind? {
        do {
            try body()
            return nil
        } catch let RatifyError.internal(kind, _) {
            return kind
        } catch {
            return nil
        }
    }
}
