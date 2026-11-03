package com.ratifyprotocol

import com.sun.jna.Library
import com.sun.jna.Native
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue

/**
 * A Rust panic surfaces as [RatifyException.Internal] with
 * [InternalErrorKind.PANIC] through public calls, and a panic inside a
 * handle's method poisons only that handle. Needs a `test-hooks` build: a
 * build without the hook fails these tests (the symbol cannot be bound), so
 * they can never be silently skipped.
 */
object PanicVectors {
    private interface Hooks : Library {
        fun ratify_ffi_test_arm_panic()
    }

    private val hooks: Hooks by lazy { Native.load("ratify_protocol_ffi", Hooks::class.java) }

    private fun kind(body: () -> Unit): InternalErrorKind? =
        try {
            body(); null
        } catch (e: RatifyException.Internal) {
            e.kind
        }

    fun query() {
        hooks.ratify_ffi_test_arm_panic()
        assertEquals(InternalErrorKind.PANIC, kind { validId("a".repeat(64)) })
        assertTrue("the next call is unaffected", validId("a".repeat(64)))
    }

    fun decoder() {
        hooks.ratify_ffi_test_arm_panic()
        assertEquals(InternalErrorKind.PANIC, kind { decodeProofBundle("{}".toByteArray()) })
        assertEquals("malformed", classOf { decodeProofBundle("{}".toByteArray()) })
    }

    fun poisonsOnlyThatHandle() {
        val key = SoftwarePrivateKey.generate()
        val other = SoftwarePrivateKey.generate()
        hooks.ratify_ffi_test_arm_panic()
        assertEquals(InternalErrorKind.PANIC, kind { ffi { key.handle.keyId() } })
        assertEquals(InternalErrorKind.POISONED, kind { ffi { key.handle.keyId() } })
        assertEquals(other.keyId, ffi { other.handle.keyId() })
    }

    fun kindsPinned() {
        assertEquals(setOf("panic", "poisoned", "random_source"), InternalErrorKind.entries.map { it.spelling }.toSet())
    }

    /** Values never share mutable storage with their callers. */
    fun valuesAreImmutable() {
        val scopes = mutableListOf("data:read")
        val k = SoftwarePrivateKey.generate().publicKey
        val sig = HybridSignature(ByteArray(64), ByteArray(3309))
        val cert = DelegationCert(2, "c", "i", k, "s", k, scopes, emptyList(), 1, 2, sig)
        val before = cert.hashCode()
        scopes += "data:write"
        assertEquals(listOf("data:read"), cert.scope)
        assertEquals(before, cert.hashCode())
        assertTrue("exposed list is unmodifiable", runCatching { (cert.scope as MutableList<String>).add("x") }.isFailure)
        val items = mutableListOf<ParamsValue>(ParamsValue.Int(1))
        val arr = ParamsValue.Array(items)
        items += ParamsValue.Null
        assertEquals(1, arr.items.size)
    }
}
