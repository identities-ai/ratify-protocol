package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiException

/**
 * Every error the SDK throws. [Protocol] and [Signing] carry a SPEC-v2 §2.7
 * class; [Internal] is reserved for a panic inside the core or a handle a
 * previous panic left unusable, and is never a protocol result.
 */
public sealed class RatifyException(message: String) : Exception(message) {
    /** The §2.7 class, or null for an internal error. */
    public abstract val errorClass: ErrorClass?

    public class Protocol(override val errorClass: ErrorClass, public val detail: String) :
        RatifyException("$detail (${errorClass.spelling})")

    public class Signing(
        override val errorClass: ErrorClass,
        public val kind: String,
        public val detail: String,
    ) : RatifyException("$detail (${errorClass.spelling}, $kind)")

    public class Internal(public val kind: InternalErrorKind, public val detail: String) :
        RatifyException("internal ${kind.spelling}: $detail") {
        override val errorClass: ErrorClass? get() = null
    }
}

/** Why an internal error occurred. None of these is a protocol result. */
public enum class InternalErrorKind(public val spelling: String) {
    /** A panic inside the core was caught at the boundary. */
    PANIC("panic"),
    /** A handle a previous panic left unusable. */
    POISONED("poisoned"),
    /** The operating-system random source failed. */
    RANDOM_SOURCE("random_source"),
}

private fun cls(spelling: String): ErrorClass =
    ErrorClass.fromSpelling(spelling) ?: error("core returned an unknown error class $spelling")

// The FFI layer emits only these kinds; the list is pinned by a test.
private fun internalKind(spelling: String): InternalErrorKind =
    InternalErrorKind.entries.firstOrNull { it.spelling == spelling }
        ?: error("FFI layer returned an unknown internal error kind $spelling")

/**
 * Run one generated-layer call and translate its failure. Every public call
 * into the generated layer goes through here.
 */
internal inline fun <T> ffi(body: () -> T): T =
    try {
        body()
    } catch (e: FfiException) {
        throw when (e) {
            is FfiException.Protocol -> RatifyException.Protocol(cls(e.`class`), e.detail)
            is FfiException.Signing -> RatifyException.Signing(cls(e.`class`), e.kind, e.detail)
            is FfiException.Internal -> RatifyException.Internal(internalKind(e.kind), e.detail)
        }
    } catch (e: RatifyException) {
        throw e
    } catch (e: kotlin.coroutines.cancellation.CancellationException) {
        throw e
    } catch (e: Exception) {
        // Every export catches its own panics; this is UniFFI's backstop
        // (its InternalException extends Exception, not RuntimeException).
        throw RatifyException.Internal(InternalErrorKind.PANIC, e.message ?: e.toString())
    }
