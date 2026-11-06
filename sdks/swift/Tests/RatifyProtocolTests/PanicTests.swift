import Foundation
import XCTest
@testable import RatifyProtocol

/// A Rust panic surfaces as `RatifyError.internal(.panic)` through public
/// calls that were formerly non-throwing and through throwing ones, and a
/// panic inside a handle's method poisons only that handle.
final class PanicTests: XCTestCase {
    func testPanicInAQueryIsInternal() {
        TestHooks.armPanic()
        XCTAssertEqual(internalKind { _ = try Ratify.validId(String(repeating: "a", count: 64)) }, .panic)
        XCTAssertTrue(try Ratify.validId(String(repeating: "a", count: 64)), "the next call is unaffected")
    }

    func testPanicInADecoderIsInternal() {
        TestHooks.armPanic()
        XCTAssertEqual(internalKind { _ = try Ratify.decodeProofBundle(Data("{}".utf8)) }, .panic)
        XCTAssertEqual(classOf { _ = try Ratify.decodeProofBundle(Data("{}".utf8)) }, "malformed")
    }

    func testPanicInAMethodPoisonsOnlyThatHandle() throws {
        let key = try SoftwarePrivateKey.generate()
        let other = try SoftwarePrivateKey.generate()
        TestHooks.armPanic()
        XCTAssertEqual(internalKind { _ = try ffi { try key.handle.keyId() } }, .panic)
        XCTAssertEqual(internalKind { _ = try ffi { try key.handle.keyId() } }, .poisoned)
        XCTAssertEqual(try ffi { try other.handle.keyId() }, other.keyId)
    }

    /// Through the public API only: a panic while a software key signs
    /// poisons that key, and every later signing call with it fails.
    func testPanicWhileSigningPoisonsTheKeyThroughThePublicAPI() throws {
        let objects = Corpus.load("objects.json")
        let cert = try Ratify.decodeDelegationCert(objectByKind(objects, "delegation_certificate").b64("wire_b64"))
        let key = Fixture.shared.privateKey("root")
        let spare = try SoftwarePrivateKey(ed25519Seed: Fixture.shared.seeds["root"]!.0, mlDsa65Seed: Fixture.shared.seeds["root"]!.1)
        XCTAssertNoThrow(try Ratify.signDelegationCert(cert, key: spare))
        TestHooks.armPanic()
        XCTAssertEqual(internalKind { _ = try Ratify.signDelegationCert(cert, key: spare) }, .panic)
        XCTAssertEqual(internalKind { _ = try Ratify.signDelegationCert(cert, key: spare) }, .poisoned)
        XCTAssertNoThrow(try Ratify.signDelegationCert(cert, key: key), "another key is unaffected")
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
