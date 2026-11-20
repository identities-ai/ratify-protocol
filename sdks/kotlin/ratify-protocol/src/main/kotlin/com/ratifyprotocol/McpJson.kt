package com.ratifyprotocol

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

// Hand-written JSON readers for the Verify MCP signer (preview). Two readers:
// the strict restricted-value-model reader that canonicalizes tool
// arguments, and a plain RFC 8259 reader for the console configuration, the
// challenge response, and the connect token body.

/** The UTF-8 bytes of [text], or null if it holds an unpaired surrogate. */
internal fun strictUtf8(text: String): ByteArray? = try {
    val buf = Charsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .encode(CharBuffer.wrap(text))
    ByteArray(buf.remaining()).also { buf.get(it) }
} catch (e: CharacterCodingException) {
    null
}

/** Unsigned lexicographic order of UTF-8 bytes. */
internal fun compareUtf8(a: ByteArray, b: ByteArray): Int {
    val n = minOf(a.size, b.size)
    for (i in 0 until n) {
        val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
        if (d != 0) return d
    }
    return a.size - b.size
}

/**
 * One UTF-8 sequence at [pos]: the code point and its length, or -1 for
 * invalid UTF-8 (truncated, overlong, an encoded surrogate, or above
 * U+10FFFF).
 */
private fun decodeUtf8(input: ByteArray, pos: Int): Pair<Int, Int> {
    val invalid = -1 to 1
    fun at(i: Int): Int = if (pos + i < input.size) input[pos + i].toInt() and 0xff else -1
    fun cont(i: Int, lo: Int = 0x80, hi: Int = 0xbf): Int? = at(i).takeIf { it in lo..hi }?.and(0x3f)
    val b0 = at(0)
    return when {
        b0 < 0x80 -> b0 to 1
        b0 in 0xc2..0xdf -> cont(1)?.let { ((b0 and 0x1f) shl 6 or it) to 2 } ?: invalid
        b0 in 0xe0..0xef -> {
            val (lo, hi) = when (b0) { 0xe0 -> 0xa0 to 0xbf; 0xed -> 0x80 to 0x9f; else -> 0x80 to 0xbf }
            val c1 = cont(1, lo, hi) ?: return invalid
            val c2 = cont(2) ?: return invalid
            ((b0 and 0x0f) shl 12 or (c1 shl 6) or c2) to 3
        }
        b0 in 0xf0..0xf4 -> {
            val (lo, hi) = when (b0) { 0xf0 -> 0x90 to 0xbf; 0xf4 -> 0x80 to 0x8f; else -> 0x80 to 0xbf }
            val c1 = cont(1, lo, hi) ?: return invalid
            val c2 = cont(2) ?: return invalid
            val c3 = cont(3) ?: return invalid
            ((b0 and 0x07) shl 18 or (c1 shl 12) or (c2 shl 6) or c3) to 4
        }
        else -> invalid
    }
}

private fun isSurrogate(r: Int): Boolean = r in 0xd800..0xdfff

private fun appendUtf8(out: ByteArrayOutputStream, r: Int) {
    when {
        r < 0x80 -> out.write(r)
        r < 0x800 -> { out.write(0xc0 or (r shr 6)); out.write(0x80 or (r and 0x3f)) }
        r < 0x10000 -> { out.write(0xe0 or (r shr 12)); out.write(0x80 or (r shr 6 and 0x3f)); out.write(0x80 or (r and 0x3f)) }
        else -> {
            out.write(0xf0 or (r shr 18)); out.write(0x80 or (r shr 12 and 0x3f))
            out.write(0x80 or (r shr 6 and 0x3f)); out.write(0x80 or (r and 0x3f))
        }
    }
}

private fun isJsonSpace(c: Int): Boolean = c == ' '.code || c == '\t'.code || c == '\r'.code || c == '\n'.code

/** Thrown inside the readers; callers turn it into their own error kind. */
internal class McpJsonException : Exception("not accepted")

private abstract class ByteReader(protected val input: ByteArray) {
    var pos = 0

    fun peek(): Int = if (pos < input.size) input[pos].toInt() and 0xff else -1

    fun space() {
        while (pos < input.size && isJsonSpace(peek())) pos++
    }

    fun literal(word: String): Boolean {
        if (pos + word.length > input.size) return false
        for (i in word.indices) if (input[pos + i].toInt() != word[i].code) return false
        pos += word.length
        return true
    }

    fun hex4(): Int? {
        if (pos + 4 > input.size) return null
        var r = 0
        for (i in 0 until 4) {
            val c = input[pos + i].toInt() and 0xff
            r = r shl 4 or when (c) {
                in '0'.code..'9'.code -> c - '0'.code
                in 'a'.code..'f'.code -> c - 'a'.code + 10
                in 'A'.code..'F'.code -> c - 'A'.code + 10
                else -> return null
            }
        }
        pos += 4
        return r
    }

    fun fail(): Nothing = throw McpJsonException()
}

/** A value of the restricted model. Strings are kept as their UTF-8 bytes. */
private sealed class Arg {
    class Obj(val members: List<Pair<ByteArray, Arg>>) : Arg()
    class Arr(val items: List<Arg>) : Arg()
    class Str(val utf8: ByteArray) : Arg()
    class Num(val value: Long) : Arg()
    class Bool(val value: Boolean) : Arg()
}

/** Largest integer magnitude the model accepts: 2^53 - 1. */
internal const val MCP_MAX_SAFE_INTEGER: Long = (1L shl 53) - 1

private class ArgReader(input: ByteArray) : ByteReader(input) {
    fun value(depth: Int): Arg {
        if (depth > Mcp.MAX_ARGUMENT_DEPTH) fail()
        space()
        return when (peek()) {
            '{'.code -> {
                pos++
                val members = ArrayList<Pair<ByteArray, Arg>>()
                val seen = HashSet<String>()
                space()
                if (peek() == '}'.code) { pos++; return Arg.Obj(members) }
                while (true) {
                    space()
                    val key = str()
                    // Valid UTF-8 maps one to one onto String, so String
                    // equality is byte equality after unescaping.
                    if (!seen.add(String(key, Charsets.UTF_8))) fail()
                    space()
                    if (peek() != ':'.code) fail()
                    pos++
                    members += key to value(depth + 1)
                    space()
                    when (peek()) {
                        ','.code -> pos++
                        '}'.code -> { pos++; return Arg.Obj(members) }
                        else -> fail()
                    }
                }
                @Suppress("UNREACHABLE_CODE") fail()
            }
            '['.code -> {
                pos++
                val items = ArrayList<Arg>()
                space()
                if (peek() == ']'.code) { pos++; return Arg.Arr(items) }
                while (true) {
                    items += value(depth + 1)
                    space()
                    when (peek()) {
                        ','.code -> pos++
                        ']'.code -> { pos++; return Arg.Arr(items) }
                        else -> fail()
                    }
                }
                @Suppress("UNREACHABLE_CODE") fail()
            }
            '"'.code -> Arg.Str(str())
            't'.code -> if (literal("true")) Arg.Bool(true) else fail()
            'f'.code -> if (literal("false")) Arg.Bool(false) else fail()
            '-'.code, in '0'.code..'9'.code -> number()
            else -> fail()
        }
    }

    /** Only the JSON integer grammar -?(0|[1-9][0-9]*), in the safe range. */
    private fun number(): Arg {
        val start = pos
        if (peek() == '-'.code) pos++
        when (peek()) {
            '0'.code -> pos++
            in '1'.code..'9'.code -> while (peek() in '0'.code..'9'.code) pos++
            else -> fail()
        }
        if (peek() == '.'.code || peek() == 'e'.code || peek() == 'E'.code) fail()
        val text = String(input, start, pos - start, Charsets.US_ASCII)
        if (text == "-0" || text.length > 17) fail()
        val n = text.toLongOrNull() ?: fail()
        if (n > MCP_MAX_SAFE_INTEGER || n < -MCP_MAX_SAFE_INTEGER) fail()
        return Arg.Num(n)
    }

    private fun allowed(r: Int): Boolean =
        !(r < 0x20 || r in 0x7f..0x9f || r == 0x2028 || r == 0x2029 || isSurrogate(r))

    fun str(): ByteArray {
        if (peek() != '"'.code) fail()
        pos++
        val out = ByteArrayOutputStream()
        while (true) {
            when (peek()) {
                -1 -> fail()
                '"'.code -> { pos++; return out.toByteArray() }
                '\\'.code -> {
                    pos++
                    val e = peek()
                    if (e == -1) fail()
                    pos++
                    when (e) {
                        '"'.code, '\\'.code, '/'.code -> out.write(e)
                        'u'.code -> {
                            var r = hex4() ?: fail()
                            if (isSurrogate(r)) {
                                if (r >= 0xdc00 || !literal("\\u")) fail()
                                val low = hex4() ?: fail()
                                if (low !in 0xdc00..0xdfff) fail()
                                r = 0x10000 + ((r - 0xd800) shl 10) + (low - 0xdc00)
                            }
                            if (!allowed(r)) fail()
                            appendUtf8(out, r)
                        }
                        // \b \f \n \r \t decode to control characters, which
                        // the model refuses; any other escape is not JSON.
                        else -> fail()
                    }
                }
                else -> {
                    val (r, size) = decodeUtf8(input, pos)
                    if (r < 0 || !allowed(r)) fail()
                    out.write(input, pos, size)
                    pos += size
                }
            }
        }
    }
}

/**
 * Canonical bytes of tool arguments under the restricted value model (see
 * [Mcp.canonicalArguments]). Throws [McpJsonException] for anything else.
 */
internal fun canonicalMcpArguments(raw: ByteArray): ByteArray {
    var s = 0
    var e = raw.size
    while (s < e && isJsonSpace(raw[s].toInt())) s++
    while (e > s && isJsonSpace(raw[e - 1].toInt())) e--
    if (s == e || (e - s == 4 && String(raw, s, 4, Charsets.US_ASCII) == "null")) return "{}".toByteArray()
    val p = ArgReader(raw)
    p.space()
    if (p.peek() != '{'.code) p.fail()
    val v = p.value(0)
    p.space()
    if (p.pos != raw.size) p.fail()
    val out = ByteArrayOutputStream()
    writeArg(out, v)
    return out.toByteArray()
}

private fun writeArg(out: ByteArrayOutputStream, v: Arg) {
    when (v) {
        is Arg.Obj -> {
            out.write('{'.code)
            v.members.sortedWith { a, b -> compareUtf8(a.first, b.first) }.forEachIndexed { i, (k, child) ->
                if (i > 0) out.write(','.code)
                writeArgString(out, k)
                out.write(':'.code)
                writeArg(out, child)
            }
            out.write('}'.code)
        }
        is Arg.Arr -> {
            out.write('['.code)
            v.items.forEachIndexed { i, child ->
                if (i > 0) out.write(','.code)
                writeArg(out, child)
            }
            out.write(']'.code)
        }
        is Arg.Str -> writeArgString(out, v.utf8)
        is Arg.Num -> out.write(v.value.toString().toByteArray(Charsets.US_ASCII))
        is Arg.Bool -> out.write((if (v.value) "true" else "false").toByteArray(Charsets.US_ASCII))
    }
}

private fun writeArgString(out: ByteArrayOutputStream, s: ByteArray) {
    out.write('"'.code)
    for (b in s) {
        if (b.toInt() == '"'.code || b.toInt() == '\\'.code) out.write('\\'.code)
        out.write(b.toInt())
    }
    out.write('"'.code)
}

/** A plain JSON value. Numbers keep their source text. */
internal sealed class McpJson {
    class Obj(val members: Map<String, McpJson>) : McpJson()
    class Arr(val items: List<McpJson>) : McpJson()
    class Str(val value: String) : McpJson()
    class Num(val text: String) : McpJson()
    class Bool(val value: Boolean) : McpJson()
    object Null : McpJson()

    companion object {
        /**
         * Deepest nesting the plain reader follows. Deeper input is refused
         * rather than risk the thread's stack.
         */
        private const val MAX_DEPTH = 512

        /**
         * Parse one RFC 8259 JSON text. A repeated object key keeps its last
         * value; invalid UTF-8 and unpaired surrogate escapes inside strings
         * decode to U+FFFD. Throws [McpJsonException] for anything else.
         */
        fun parse(input: ByteArray): McpJson {
            val r = Reader(input)
            val v = r.value(0)
            r.space()
            if (r.pos != input.size) r.fail()
            return v
        }
    }

    private class Reader(input: ByteArray) : ByteReader(input) {
        fun value(depth: Int): McpJson {
            if (depth > MAX_DEPTH) fail()
            space()
            return when (peek()) {
                '{'.code -> {
                    pos++
                    val members = LinkedHashMap<String, McpJson>()
                    space()
                    if (peek() == '}'.code) { pos++; return Obj(members) }
                    while (true) {
                        space()
                        val key = str()
                        space()
                        if (peek() != ':'.code) fail()
                        pos++
                        members.remove(key)
                        members[key] = value(depth + 1)
                        space()
                        when (peek()) {
                            ','.code -> pos++
                            '}'.code -> { pos++; return Obj(members) }
                            else -> fail()
                        }
                    }
                    @Suppress("UNREACHABLE_CODE") fail()
                }
                '['.code -> {
                    pos++
                    val items = ArrayList<McpJson>()
                    space()
                    if (peek() == ']'.code) { pos++; return Arr(items) }
                    while (true) {
                        items += value(depth + 1)
                        space()
                        when (peek()) {
                            ','.code -> pos++
                            ']'.code -> { pos++; return Arr(items) }
                            else -> fail()
                        }
                    }
                    @Suppress("UNREACHABLE_CODE") fail()
                }
                '"'.code -> Str(str())
                't'.code -> if (literal("true")) Bool(true) else fail()
                'f'.code -> if (literal("false")) Bool(false) else fail()
                'n'.code -> if (literal("null")) Null else fail()
                '-'.code, in '0'.code..'9'.code -> number()
                else -> fail()
            }
        }

        private fun digits(): Int {
            val start = pos
            while (peek() in '0'.code..'9'.code) pos++
            return pos - start
        }

        private fun number(): McpJson {
            val start = pos
            if (peek() == '-'.code) pos++
            when (peek()) {
                '0'.code -> pos++
                in '1'.code..'9'.code -> digits()
                else -> fail()
            }
            if (peek() == '.'.code) {
                pos++
                if (digits() == 0) fail()
            }
            if (peek() == 'e'.code || peek() == 'E'.code) {
                pos++
                if (peek() == '+'.code || peek() == '-'.code) pos++
                if (digits() == 0) fail()
            }
            return Num(String(input, start, pos - start, Charsets.US_ASCII))
        }

        fun str(): String {
            if (peek() != '"'.code) fail()
            pos++
            val out = ByteArrayOutputStream()
            while (true) {
                val c = peek()
                when {
                    c == -1 || c < 0x20 -> fail()
                    c == '"'.code -> {
                        pos++
                        return Charsets.UTF_8.newDecoder()
                            .onMalformedInput(CodingErrorAction.REPLACE)
                            .onUnmappableCharacter(CodingErrorAction.REPLACE)
                            .decode(ByteBuffer.wrap(out.toByteArray())).toString()
                    }
                    c == '\\'.code -> {
                        pos++
                        val e = peek()
                        pos++
                        when (e) {
                            '"'.code, '\\'.code, '/'.code -> out.write(e)
                            'b'.code -> out.write(0x08)
                            'f'.code -> out.write(0x0c)
                            'n'.code -> out.write(0x0a)
                            'r'.code -> out.write(0x0d)
                            't'.code -> out.write(0x09)
                            'u'.code -> {
                                var r = hex4() ?: fail()
                                if (isSurrogate(r)) {
                                    val save = pos
                                    val low = if (r < 0xdc00 && literal("\\u")) hex4() else null
                                    if (low != null && low in 0xdc00..0xdfff) {
                                        r = 0x10000 + ((r - 0xd800) shl 10) + (low - 0xdc00)
                                    } else {
                                        pos = save
                                        r = 0xfffd
                                    }
                                }
                                appendUtf8(out, r)
                            }
                            else -> fail()
                        }
                    }
                    else -> { out.write(c); pos++ }
                }
            }
        }
    }
}

/** Whether [data] is entirely valid UTF-8 (no overlong form, encoded surrogate, or value above U+10FFFF). */
internal fun validUtf8(data: ByteArray): Boolean {
    var pos = 0
    while (pos < data.size) {
        val (r, size) = decodeUtf8(data, pos)
        if (r < 0) return false
        pos += size
    }
    return true
}
