import Foundation
import RatifyProtocol

/// Signs an SDK request outside the SDK, as an HSM or KMS would (test-hooks
/// build only; the SDK exports no raw signer). Direct mode.
@_silgen_name("ratify_ffi_test_provider_sign")
private func providerSign(_ ed: UnsafePointer<UInt8>, _ ml: UnsafePointer<UInt8>, _ msg: UnsafePointer<UInt8>, _ msgLen: Int,
                          _ ctx: UnsafePointer<UInt8>, _ ctxLen: Int, _ outEd: UnsafeMutablePointer<UInt8>,
                          _ outMl: UnsafeMutablePointer<UInt8>) -> Int32

func emulatedProviderSign(seeds: (Data, Data), message: Data, context: Data) -> HybridSignature? {
    var ed = [UInt8](repeating: 0, count: 64)
    var ml = [UInt8](repeating: 0, count: 3309)
    let rc = [UInt8](seeds.0).withUnsafeBufferPointer { e in
        [UInt8](seeds.1).withUnsafeBufferPointer { m in
            [UInt8](message).withUnsafeBufferPointer { msg in
                // A non-null pointer even for an empty context.
                ([UInt8](context) + [0]).withUnsafeBufferPointer { c in
                    providerSign(e.baseAddress!, m.baseAddress!, msg.baseAddress!, msg.count, c.baseAddress!, context.count, &ed, &ml)
                }
            }
        }
    }
    return rc == 0 ? HybridSignature(ed25519: Data(ed), mlDsa65: Data(ml)) : nil
}

/// A direct-mode provider holding one fixture key, counting every call.
final class ProviderSigner: ExternalSigner, @unchecked Sendable {
    let name: String
    private let lock = NSLock()
    private var n = 0
    init(_ name: String) { self.name = name }

    var calls: Int { lock.lock(); defer { lock.unlock() }; return n }
    private func count() { lock.withLock { n += 1 } }

    var publicKey: HybridPublicKey { count(); return Fixture.shared.key(name) }
    var mode: SignerMode { count(); return .direct }
    func sign(_ request: SignRequest) async throws -> HybridSignature {
        count()
        guard request.publicKey == Fixture.shared.key(name), let ctx = request.mlDsaContext else {
            throw ProviderError.refused
        }
        guard let sig = emulatedProviderSign(seeds: Fixture.shared.seeds[name]!, message: request.message, context: ctx) else {
            throw ProviderError.refused
        }
        return sig
    }
}

enum ProviderError: Error { case refused, scripted }
