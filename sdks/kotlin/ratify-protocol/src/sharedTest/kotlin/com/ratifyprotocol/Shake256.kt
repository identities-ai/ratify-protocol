package com.ratifyprotocol

/**
 * SHAKE256 (FIPS 202), written here so the ML-DSA `tr` check is independent
 * of the core. Only used by the tests.
 */
object Shake256 {
    // The FIPS 202 round constants.
    private val rc = listOf(
        "0000000000000001",
        "0000000000008082",
        "800000000000808A",
        "8000000080008000",
        "000000000000808B",
        "0000000080000001",
        "8000000080008081",
        "8000000000008009",
        "000000000000008A",
        "0000000000000088",
        "0000000080008009",
        "000000008000000A",
        "000000008000808B",
        "800000000000008B",
        "8000000000008089",
        "8000000000008003",
        "8000000000008002",
        "8000000000000080",
        "000000000000800A",
        "800000008000000A",
        "8000000080008081",
        "8000000000008080",
        "0000000080000001",
        "8000000080008008",
    ).map { java.lang.Long.parseUnsignedLong(it, 16) }.toLongArray()
    private val rot = intArrayOf(0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14)

    private fun keccak(a: LongArray) {
        val c = LongArray(5)
        val b = LongArray(25)
        for (round in 0 until 24) {
            for (x in 0 until 5) c[x] = a[x] xor a[x + 5] xor a[x + 10] xor a[x + 15] xor a[x + 20]
            for (x in 0 until 5) {
                val d = c[(x + 4) % 5] xor java.lang.Long.rotateLeft(c[(x + 1) % 5], 1)
                for (y in 0 until 5) a[x + 5 * y] = a[x + 5 * y] xor d
            }
            for (x in 0 until 5) for (y in 0 until 5) {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = java.lang.Long.rotateLeft(a[x + 5 * y], rot[x + 5 * y])
            }
            for (x in 0 until 5) for (y in 0 until 5) {
                a[x + 5 * y] = b[x + 5 * y] xor (b[(x + 1) % 5 + 5 * y].inv() and b[(x + 2) % 5 + 5 * y])
            }
            a[0] = a[0] xor rc[round]
        }
    }

    fun hash(input: ByteArray, outputLength: Int): ByteArray {
        val rate = 136
        val state = LongArray(25)
        val padded = (input.size / rate + 1) * rate
        val msg = input.copyOf(padded)
        msg[input.size] = (msg[input.size].toInt() xor 0x1F).toByte()
        msg[padded - 1] = (msg[padded - 1].toInt() or 0x80).toByte()
        for (block in 0 until padded step rate) {
            for (i in 0 until rate / 8) {
                var lane = 0L
                for (j in 0 until 8) lane = lane or ((msg[block + 8 * i + j].toLong() and 0xFF) shl (8 * j))
                state[i] = state[i] xor lane
            }
            keccak(state)
        }
        val out = ByteArray(outputLength)
        var n = 0
        while (true) {
            for (i in 0 until rate / 8) for (j in 0 until 8) {
                out[n++] = ((state[i] ushr (8 * j)) and 0xFF).toByte()
                if (n == outputLength) return out
            }
            keccak(state)
        }
    }
}
