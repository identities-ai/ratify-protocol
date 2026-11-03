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
        RatifyException("internal ${kind.name.lowercase()}: $detail") {
        override val errorClass: ErrorClass? get() = null
    }
}

public enum class InternalErrorKind { PANIC, POISONED }

private fun cls(spelling: String): ErrorClass =
    ErrorClass.fromSpelling(spelling) ?: error("core returned an unknown error class $spelling")

/** Run one generated-layer call and translate its failure. */
internal inline fun <T> ffi(body: () -> T): T =
    try {
        body()
    } catch (e: FfiException) {
        throw when (e) {
            is FfiException.Protocol -> RatifyException.Protocol(cls(e.`class`), e.detail)
            is FfiException.Signing -> RatifyException.Signing(cls(e.`class`), e.kind, e.detail)
            is FfiException.Internal -> RatifyException.Internal(
                if (e.kind == "poisoned") InternalErrorKind.POISONED else InternalErrorKind.PANIC,
                e.detail,
            )
        }
    } catch (e: RatifyException) {
        throw e
    } catch (e: RuntimeException) {
        // The generated layer's other failure is a caught Rust panic.
        throw RatifyException.Internal(InternalErrorKind.PANIC, e.message ?: e.toString())
    }
