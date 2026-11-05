package com.ratifyprotocol

import androidx.annotation.RestrictTo
import com.ratifyprotocol.internal.ffi.FfiReferenceTrustRegistry
import com.ratifyprotocol.internal.ffi.ffiReferenceTrustRegistry

/** Bridge for the separately packaged reference trust registry. */
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class ReferenceTrustRegistryBridge(records: List<HybridPublicKey>) {
    private val handle: FfiReferenceTrustRegistry = ffi { ffiReferenceTrustRegistry(records.map(HybridPublicKey::toFfi)) }

    public fun resolve(chain: List<DelegationCert>): TrustResolution {
        val answer = ffi { handle.resolve(chain.map(DelegationCert::toFfi)) }
        val outcome = TrustOutcome.fromSpelling(answer.outcome)
            ?: throw RatifyException.Internal(InternalErrorKind.PANIC, "unknown reference trust outcome")
        return TrustResolution(outcome, HybridPublicKey(answer.rootKey))
    }
}
