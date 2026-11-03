import Foundation

/// SHAKE256 (FIPS 202), written here so the ML-DSA `tr` check is
/// independent of the core. Only used by the tests.
enum Shake256 {
    private static let rc: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    private static let rot: [Int] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]

    private static func keccak(_ a: inout [UInt64]) {
        for round in 0..<24 {
            var c = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 { c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] }
            for x in 0..<5 {
                let d = c[(x + 4) % 5] ^ ((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63))
                for y in 0..<5 { a[x + 5 * y] ^= d }
            }
            var b = [UInt64](repeating: 0, count: 25)
            for x in 0..<5 {
                for y in 0..<5 {
                    let r = rot[x + 5 * y]
                    let v = a[x + 5 * y]
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = r == 0 ? v : (v << UInt64(r)) | (v >> UInt64(64 - r))
                }
            }
            for x in 0..<5 {
                for y in 0..<5 {
                    a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y])
                }
            }
            a[0] ^= rc[round]
        }
    }

    static func hash(_ input: Data, outputLength: Int) -> Data {
        let rate = 136
        var state = [UInt64](repeating: 0, count: 25)
        var msg = [UInt8](input)
        msg.append(0x1F)
        while msg.count % rate != 0 { msg.append(0) }
        msg[msg.count - 1] |= 0x80
        for block in stride(from: 0, to: msg.count, by: rate) {
            for i in 0..<(rate / 8) {
                var lane: UInt64 = 0
                for j in 0..<8 { lane |= UInt64(msg[block + 8 * i + j]) << UInt64(8 * j) }
                state[i] ^= lane
            }
            keccak(&state)
        }
        var out = Data()
        while true {
            for i in 0..<(rate / 8) {
                for j in 0..<8 {
                    out.append(UInt8((state[i] >> UInt64(8 * j)) & 0xFF))
                    if out.count == outputLength { return out }
                }
            }
            keccak(&state)
        }
    }
}
