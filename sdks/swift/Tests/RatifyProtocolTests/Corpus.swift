import Foundation
import XCTest
import RatifyProtocol

/// Reads the shared corpus in place (testvectors/v2), never a copy.
enum Corpus {
    static let dir: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()   // RatifyProtocolTests
        .deletingLastPathComponent()   // Tests
        .deletingLastPathComponent()   // swift
        .deletingLastPathComponent()   // sdks
        .deletingLastPathComponent()   // repo root
        .appendingPathComponent("testvectors/v2")

    static func load(_ name: String) -> [String: Any] {
        let data = try! Data(contentsOf: dir.appendingPathComponent(name))
        return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    static func url(_ name: String) -> URL { dir.appendingPathComponent(name) }
}

extension Dictionary where Key == String, Value == Any {
    func s(_ k: String) -> String { self[k] as! String }
    func arr(_ k: String) -> [[String: Any]] { self[k] as! [[String: Any]] }
    func obj(_ k: String) -> [String: Any] { self[k] as! [String: Any] }
    func strings(_ k: String) -> [String] { self[k] as! [String] }
    func bool(_ k: String) -> Bool { self[k] as! Bool }
    func int(_ k: String) -> Int { (self[k] as! NSNumber).intValue }
    func b64(_ k: String) -> Data { Data(base64Encoded: s(k))! }
    func hex(_ k: String) -> Data { Data(hex: s(k)) }
}

extension Data {
    init(hex: String) {
        precondition(hex.count % 2 == 0, "odd hex")
        var out = Data(capacity: hex.count / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            out.append(UInt8(hex[i..<j], radix: 16)!)
            i = j
        }
        self = out
    }
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

/// Counts executed checks per group. `finish` fails unless every group ran
/// exactly the number of cases computed from the file: no case is skipped.
final class Tally {
    private var counts: [String: Int] = [:]
    private var failures: [String] = []

    func check(_ group: String, _ name: String, _ ok: Bool, _ detail: @autoclosure () -> String = "",
               file: StaticString = #filePath, line: UInt = #line) {
        counts[group, default: 0] += 1
        if !ok {
            failures.append("\(group)/\(name): \(detail())")
            XCTFail("\(group)/\(name): \(detail())", file: file, line: line)
        }
    }

    func finish(_ expected: [(String, Int)], file: StaticString = #filePath, line: UInt = #line) {
        for (g, n) in expected {
            XCTAssertEqual(counts[g, default: 0], n, "group \(g) executed count", file: file, line: line)
            XCTAssertGreaterThan(n, 0, "group \(g) must have cases", file: file, line: line)
        }
        XCTAssertEqual(Set(counts.keys), Set(expected.map(\.0)), "groups executed", file: file, line: line)
    }
}

/// The §2.7 class a call fails with, "ok" on success, "internal" otherwise.
func classOf(_ body: () throws -> Void) -> String {
    do {
        try body()
        return "ok"
    } catch let e as RatifyError {
        return e.errorClass?.rawValue ?? "internal"
    } catch {
        return "non-ratify error \(error)"
    }
}


/// The objects.json entry of one kind.
func objectByKind(_ objects: [String: Any], _ kind: String) -> [String: Any] {
    objects.arr("objects").first { $0.s("kind") == kind }!
}

/// `wire` with one top-level string field replaced, re-canonicalized.
func setTopLevelString(_ wire: Data, _ field: String, _ value: String) -> Data {
    var obj = try! JSONSerialization.jsonObject(with: wire) as! [String: Any]
    obj[field] = value
    return try! Ratify.canonicalJSON(try! JSONSerialization.data(withJSONObject: obj))
}
