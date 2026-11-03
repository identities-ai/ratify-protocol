import CryptoKit
import Foundation
import XCTest
import RatifyProtocol

/// annex-a.json through the public API: pinned clauses, canonical JSON,
/// strict-decode rejections, and the scope vocabulary, expansion and
/// intersection rules.
final class AnnexATests: XCTestCase {
    func isCanonicalObject(_ d: Data) -> Bool {
        d.first == UInt8(ascii: "{") && (try? Ratify.canonicalJSON(d)) == d
    }

    func testAnnexACorpus() throws {
        let f = Corpus.load("annex-a.json")
        let t = Tally()

        let annex = try String(contentsOf: Corpus.url("../../SPEC-v2-ANNEX-A.md"), encoding: .utf8)
        let lines = annex.components(separatedBy: "\n")
        for c in f.arr("clauses") {
            let id = c.s("id")
            var ok = false
            if let b = lines.firstIndex(of: "<!-- annex-a:begin \(id) -->"),
               let e = lines.firstIndex(of: "<!-- annex-a:end \(id) -->"), e > b + 1 {
                let block = lines[(b + 1)..<e].joined(separator: "\n")
                let digest = Data(SHA256.hash(data: Data(block.utf8))).hex
                ok = block.utf8.count == c.int("bytes") && digest == c.s("sha256") && annex.contains("`\(c.s("sha256"))`")
            }
            t.check("clauses", id, ok, "clause bytes or digest differ")
        }

        for v in f.arr("canonical_json") {
            let input = v.b64("input_b64")
            let got = try? Ratify.canonicalJSON(input)
            let want = Data(v.s("canonical").utf8)
            let canonicalInput = isCanonicalObject(input)
            let ok = got == want && isCanonicalObject(want)
                && canonicalInput == v.bool("input_is_canonical")
                && canonicalInput == (got == input)
            t.check("canonical_json", v.s("name"), ok, "\(String(describing: got))")
        }
        for v in f.arr("strict_decode_rejections") {
            let input = v.b64("input_b64")
            t.check("strict_decode_rejections", v.s("name"), (try? Ratify.canonicalJSON(input)) == nil, "accepted")
        }

        let vocab = f.obj("vocabulary")
        let canonical = vocab.strings("canonical")
        t.check("vocabulary", "canonical", Ratify.scopeVocabulary == canonical, "\(Ratify.scopeVocabulary)")
        let sensitive = canonical.filter(Ratify.isSensitiveScope)
        t.check("vocabulary", "sensitive", sensitive == vocab.strings("sensitive"), "\(sensitive)")
        for c in canonical {
            t.check("vocabulary", c, (try? Ratify.validateScopes([c])) != nil, "rejected")
        }
        let wildcards = vocab.obj("wildcards")
        t.check("vocabulary", "wildcard count", wildcards.count == Ratify.scopeWildcards.count, "count")
        for (w, want) in wildcards {
            let got = Ratify.expandScopes([w])
            let want = want as! [String]
            t.check("wildcards", w, got == want && want.allSatisfy { !Ratify.isSensitiveScope($0) }, "\(got)")
        }
        for v in f.arr("scope_validation") {
            let valid = (try? Ratify.validateScopes(v.strings("scopes"))) != nil
            t.check("scope_validation", v.s("name"), valid == v.bool("valid"), "valid=\(valid)")
        }
        for v in f.arr("scope_expansion") {
            let got = Ratify.expandScopes(v.strings("scopes"))
            t.check("scope_expansion", v.s("name"), got == v.strings("expanded"), "\(got)")
        }
        for v in f.arr("scope_intersection") {
            let lists = v["lists"] as! [[String]]
            let got = Ratify.intersectScopes(lists)
            t.check("scope_intersection", v.s("name"), got == v.strings("effective"), "\(got)")
        }
        t.finish([
            ("clauses", f.arr("clauses").count),
            ("canonical_json", f.arr("canonical_json").count),
            ("strict_decode_rejections", f.arr("strict_decode_rejections").count),
            ("vocabulary", canonical.count + 3),
            ("wildcards", wildcards.count),
            ("scope_validation", f.arr("scope_validation").count),
            ("scope_expansion", f.arr("scope_expansion").count),
            ("scope_intersection", f.arr("scope_intersection").count),
        ])
    }
}
