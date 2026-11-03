package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.ffiCanonicalJson
import com.ratifyprotocol.internal.ffi.ffiErrorClassSpellings
import com.ratifyprotocol.internal.ffi.ffiExpandScopes
import com.ratifyprotocol.internal.ffi.ffiIntersectScopes
import com.ratifyprotocol.internal.ffi.ffiIsSensitiveScope
import com.ratifyprotocol.internal.ffi.ffiScopeVocabulary
import com.ratifyprotocol.internal.ffi.ffiScopeWildcards
import com.ratifyprotocol.internal.ffi.ffiValidateScopes

/** The §2.7 class spellings in table order, as the core defines them. */
public fun errorClassSpellings(): List<String> = ffi { ffiErrorClassSpellings() }

/**
 * The canonical form of a JSON text (SPEC-v2 Annex A). Throws `malformed` for
 * any input the strict decoder rejects.
 */
public fun canonicalJson(data: ByteArray): ByteArray = ffi { ffiCanonicalJson(data) }

/** Validate a scope list against the v2 vocabulary rules. */
public fun validateScopes(scopes: List<String>): Unit = ffi { ffiValidateScopes(scopes.toList()) }

/** Every canonical scope, sorted. */
public fun scopeVocabulary(): List<String> = ffi { ffiScopeVocabulary() }

/** Each wildcard scope and the scopes it expands to. */
public fun scopeWildcards(): Map<String, List<String>> = ffi { ffiScopeWildcards() }

public fun isSensitiveScope(scope: String): Boolean = ffi { ffiIsSensitiveScope(scope) }

public fun expandScopes(scopes: List<String>): List<String> = ffi { ffiExpandScopes(scopes.toList()) }

public fun intersectScopes(lists: List<List<String>>): List<String> = ffi { ffiIntersectScopes(lists.map { it.toList() }) }
