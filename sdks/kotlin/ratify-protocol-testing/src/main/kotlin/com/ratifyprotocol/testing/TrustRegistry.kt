package com.ratifyprotocol.testing

import com.ratifyprotocol.DelegationCert
import com.ratifyprotocol.HybridPublicKey
import com.ratifyprotocol.ReferenceTrustRegistryBridge
import com.ratifyprotocol.TrustProvider
import com.ratifyprotocol.TrustResolution

/** Candidate-record resolver for conformance tests. Records must come from authenticated configuration. */
public class TrustRegistry(records: List<HybridPublicKey>) : TrustProvider {
    private val bridge = ReferenceTrustRegistryBridge(records)

    override suspend fun resolve(chain: List<DelegationCert>): TrustResolution = bridge.resolve(chain)
}
