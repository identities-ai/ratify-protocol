import Foundation
import XCTest
import RatifyProtocol

final class KeysTests: XCTestCase {
    func testGenerateIsFreshAndConsistent() throws {
        let a = try SoftwarePrivateKey.generate()
        let b = try SoftwarePrivateKey.generate()
        XCTAssertNotEqual(a.keyId, b.keyId)
        XCTAssertEqual(try Ratify.keyId(a.publicKey), a.keyId)
        XCTAssertEqual(a.publicKey.ed25519.count, 32)
        XCTAssertEqual(a.publicKey.mlDsa65.count, 1952)
    }

    func testBadSeedLengthIsMalformed() {
        XCTAssertEqual(classOf { _ = try SoftwarePrivateKey(ed25519Seed: Data(count: 31), mlDsa65Seed: Data(count: 32)) },
                       "malformed")
    }

    func testErrorClassesPinnedToCore() throws {
        XCTAssertEqual(ErrorClass.allCases.map(\.rawValue), try Ratify.errorClassSpellings())
    }
}
