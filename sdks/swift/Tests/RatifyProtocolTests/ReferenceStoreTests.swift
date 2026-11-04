import Foundation
import RatifyProtocol
import RatifyProtocolTestSupport
import XCTest

final class ReferenceStoreTests: XCTestCase {
    func testClockAndCloneHaveIndependentState() throws {
        let key = try SoftwarePrivateKey(ed25519Seed: Data(repeating: 1, count: 32), mlDsa65Seed: Data(repeating: 2, count: 32))
        let store = try Store(now: 100, leaseSeconds: 5, logId: String(repeating: "a", count: 32), verifierKey: key)
        XCTAssertEqual(try store.now(), 100)
        try store.setTime(101)
        let copy = try store.cloneStore()
        XCTAssertEqual(try copy.now(), 101)
        try copy.setTime(200)
        XCTAssertEqual(try store.now(), 101)
        XCTAssertEqual(try copy.now(), 200)
        XCTAssertEqual(try store.logLength(), 0)
        XCTAssertEqual(try store.abandonPendingReceipts(), [])
        XCTAssertEqual(classOf { _ = try Store(now: 100, leaseSeconds: 0, logId: String(repeating: "a", count: 32), verifierKey: key) }, "configuration_invalid")
    }
}
