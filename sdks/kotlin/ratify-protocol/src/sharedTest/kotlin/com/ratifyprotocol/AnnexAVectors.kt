package com.ratifyprotocol

/**
 * annex-a.json through the public API: pinned clauses, canonical JSON,
 * strict-decode rejections, and the scope vocabulary, expansion and
 * intersection rules.
 */
object AnnexAVectors {
    private fun isCanonicalObject(d: ByteArray): Boolean =
        d.isNotEmpty() && d[0] == '{'.code.toByte() && runCatching { canonicalJson(d) }.getOrNull()?.contentEquals(d) == true

    fun corpus(annex: String) {
        val f = Corpus.load("annex-a.json")
        val t = Tally("annex-a.json")

        val lines = annex.split("\n")
        for (c in f.arr("clauses")) {
            val id = c.getString("id")
            val b = lines.indexOf("<!-- annex-a:begin $id -->")
            val e = lines.indexOf("<!-- annex-a:end $id -->")
            val ok = b >= 0 && e > b + 1 && run {
                val block = lines.subList(b + 1, e).joinToString("\n")
                val bytes = block.toByteArray(Charsets.UTF_8)
                bytes.size == c.getInt("bytes") && sha256(bytes).hex() == c.getString("sha256") &&
                    annex.contains("`${c.getString("sha256")}`")
            }
            t.check("clauses", id, ok) { "clause bytes or digest differ" }
        }

        for (v in f.arr("canonical_json")) {
            val input = v.b64("input_b64")
            val got = runCatching { canonicalJson(input) }.getOrNull()
            val want = v.getString("canonical").toByteArray(Charsets.UTF_8)
            val canonicalInput = isCanonicalObject(input)
            val ok = got != null && got.contentEquals(want) && isCanonicalObject(want) &&
                canonicalInput == v.getBoolean("input_is_canonical") &&
                canonicalInput == got.contentEquals(input)
            t.check("canonical_json", v.getString("name"), ok) { got?.let { String(it) } ?: "rejected" }
        }
        for (v in f.arr("strict_decode_rejections")) {
            val input = v.b64("input_b64")
            t.check("strict_decode_rejections", v.getString("name"), classOf { canonicalJson(input) } != "ok") { "accepted" }
        }

        val vocab = f.getJSONObject("vocabulary")
        val canonical = vocab.strings("canonical")
        t.check("vocabulary", "canonical", scopeVocabulary() == canonical) { "${scopeVocabulary()}" }
        val sensitive = canonical.filter(::isSensitiveScope)
        t.check("vocabulary", "sensitive", sensitive == vocab.strings("sensitive")) { "$sensitive" }
        for (c in canonical) {
            t.check("vocabulary", c, classOf { validateScopes(listOf(c)) } == "ok") { "rejected" }
        }
        val wildcards = vocab.getJSONObject("wildcards")
        t.check("vocabulary", "wildcard count", wildcards.length() == scopeWildcards().size) { "count" }
        for (w in wildcards.keys()) {
            val got = expandScopes(listOf(w))
            val want = wildcards.getJSONArray(w).strings()
            t.check("wildcards", w, got == want && want.none(::isSensitiveScope)) { "$got" }
        }
        for (v in f.arr("scope_validation")) {
            val valid = classOf { validateScopes(v.strings("scopes")) } == "ok"
            t.check("scope_validation", v.getString("name"), valid == v.getBoolean("valid")) { "valid=$valid" }
        }
        for (v in f.arr("scope_expansion")) {
            val got = expandScopes(v.strings("scopes"))
            t.check("scope_expansion", v.getString("name"), got == v.strings("expanded")) { "$got" }
        }
        for (v in f.arr("scope_intersection")) {
            val a = v.getJSONArray("lists")
            val lists = List(a.length()) { a.getJSONArray(it).strings() }
            val got = intersectScopes(lists)
            t.check("scope_intersection", v.getString("name"), got == v.strings("effective")) { "$got" }
        }
        t.finish(
            listOf(
                "clauses" to f.getJSONArray("clauses").length(),
                "canonical_json" to f.getJSONArray("canonical_json").length(),
                "strict_decode_rejections" to f.getJSONArray("strict_decode_rejections").length(),
                "vocabulary" to canonical.size + 3,
                "wildcards" to wildcards.length(),
                "scope_validation" to f.getJSONArray("scope_validation").length(),
                "scope_expansion" to f.getJSONArray("scope_expansion").length(),
                "scope_intersection" to f.getJSONArray("scope_intersection").length(),
            ),
        )
    }
}
