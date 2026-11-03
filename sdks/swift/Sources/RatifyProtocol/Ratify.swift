import Foundation

/// Namespace for the SDK's free functions.
public enum Ratify {
    /// The §2.7 class spellings in table order, as the core defines them.
    public static var errorClassSpellings: [String] { ffiErrorClassSpellings() }

    /// The canonical form of a JSON text (SPEC-v2 Annex A). Throws
    /// `malformed` for any input the strict decoder rejects.
    public static func canonicalJSON(_ data: Data) throws(RatifyError) -> Data {
        try ffi { try ffiCanonicalJson(data: data) }
    }

    /// Validate a scope list against the v2 vocabulary rules.
    public static func validateScopes(_ scopes: [String]) throws(RatifyError) {
        try ffi { try ffiValidateScopes(scopes: scopes) }
    }

    /// Every canonical scope, sorted.
    public static var scopeVocabulary: [String] { ffiScopeVocabulary() }

    /// Each wildcard scope and the scopes it expands to.
    public static var scopeWildcards: [String: [String]] { ffiScopeWildcards() }

    public static func isSensitiveScope(_ scope: String) -> Bool {
        ffiIsSensitiveScope(scope: scope)
    }

    public static func expandScopes(_ scopes: [String]) -> [String] {
        ffiExpandScopes(scopes: scopes)
    }

    public static func intersectScopes(_ lists: [[String]]) -> [String] {
        ffiIntersectScopes(lists: lists)
    }
}
