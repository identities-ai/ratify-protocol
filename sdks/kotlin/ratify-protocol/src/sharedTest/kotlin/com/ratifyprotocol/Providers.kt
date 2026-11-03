package com.ratifyprotocol

import com.sun.jna.Library
import com.sun.jna.Native
import java.util.concurrent.atomic.AtomicInteger

/** Signs an SDK request outside the SDK, as an HSM or KMS would (test-hooks build only). */
private interface ProviderHooks : Library {
    fun ratify_ffi_test_provider_sign(
        ed: ByteArray, ml: ByteArray, msg: ByteArray, msgLen: Long, ctx: ByteArray, ctxLen: Long,
        outEd: ByteArray, outMl: ByteArray,
    ): Int
}

private val providerHooks: ProviderHooks by lazy { Native.load("ratify_protocol_ffi", ProviderHooks::class.java) }

fun emulatedProviderSign(seeds: Pair<ByteArray, ByteArray>, message: ByteArray, context: ByteArray): HybridSignature? {
    val ed = ByteArray(64)
    val ml = ByteArray(3309)
    val rc = providerHooks.ratify_ffi_test_provider_sign(
        seeds.first, seeds.second, message, message.size.toLong(), context + byteArrayOf(0), context.size.toLong(), ed, ml,
    )
    return if (rc == 0) HybridSignature(ed, ml) else null
}

class ProviderException(message: String) : Exception(message)

/** A direct-mode provider holding one fixture key, counting every call. */
class ProviderSigner(private val name: String) : ExternalSigner {
    private val n = AtomicInteger()
    val calls: Int get() = n.get()

    override val publicKey: HybridPublicKey get() = Fixture.key(name).also { n.incrementAndGet() }
    override val mode: SignerMode get() = SignerMode.DIRECT.also { n.incrementAndGet() }

    override suspend fun sign(request: SignRequest): HybridSignature {
        n.incrementAndGet()
        val ctx = request.mlDsaContext
        if (request.publicKey != Fixture.key(name) || ctx == null) throw ProviderException("refused")
        return emulatedProviderSign(Fixture.seeds.getValue(name), request.message, ctx) ?: throw ProviderException("refused")
    }
}
