import CryptoKit
import Foundation
import RatifyProtocol

/// annex-a.json through the public API: pinned clauses, canonical JSON,
/// strict-decode rejections, and the scope vocabulary, expansion and
/// intersection rules.
enum AnnexARunner {
    static func isCanonicalObject(_ d: Data) -> Bool {
        d.first == UInt8(ascii: "{") && (try? Ratify.canonicalJSON(d)) == d
    }

    static func run() throws {
        let f = Corpus.load("annex-a.json")
        let t = Tally("annex-a.json")

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
        let ours = try Ratify.scopeVocabulary()
        t.check("vocabulary", "canonical", ours == canonical, "\(ours)")
        let sensitive = try canonical.filter { s throws(RatifyError) in try Ratify.isSensitiveScope(s) }
        t.check("vocabulary", "sensitive", sensitive == vocab.strings("sensitive"), "\(sensitive)")
        for c in canonical {
            t.check("vocabulary", c, (try? Ratify.validateScopes([c])) != nil, "rejected")
        }
        let wildcards = vocab.obj("wildcards")
        t.check("vocabulary", "wildcard count", wildcards.count == (try Ratify.scopeWildcards()).count, "count")
        for (w, want) in wildcards {
            let got = try Ratify.expandScopes([w])
            let want = want as! [String]
            let noneSensitive = try want.allSatisfy { s throws(RatifyError) in try !Ratify.isSensitiveScope(s) }
            t.check("wildcards", w, got == want && noneSensitive, "\(got)")
        }
        for v in f.arr("scope_validation") {
            let valid = (try? Ratify.validateScopes(v.strings("scopes"))) != nil
            t.check("scope_validation", v.s("name"), valid == v.bool("valid"), "valid=\(valid)")
        }
        for v in f.arr("scope_expansion") {
            let got = try Ratify.expandScopes(v.strings("scopes"))
            t.check("scope_expansion", v.s("name"), got == v.strings("expanded"), "\(got)")
        }
        for v in f.arr("scope_intersection") {
            let lists = v["lists"] as! [[String]]
            let got = try Ratify.intersectScopes(lists)
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
