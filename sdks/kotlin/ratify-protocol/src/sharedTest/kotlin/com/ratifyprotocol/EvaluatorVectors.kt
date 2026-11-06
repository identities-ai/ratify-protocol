package com.ratifyprotocol

import org.json.JSONObject
import org.json.JSONArray

/** All standard evaluator and request-context cases in the shared corpus. */
object EvaluatorVectors {
    private fun context(v: JSONObject): ConstraintContext {
        val counts = v.optJSONObject("extension_counts")?.let { o ->
            o.keys().asSequence().associateWith(o::getLong)
        } ?: emptyMap()
        val values = v.optJSONObject("extension_values")?.let { o ->
            o.keys().asSequence().associateWith(o::getString)
        } ?: emptyMap()
        return ConstraintContext(extensionCounts = counts, extensionValues = values)
    }

    fun run() {
        val corpus = Corpus.load("evaluator-profiles.json")
        val tally = Tally("evaluator-profiles.json")
        var cases = 0
        for (profile in corpus.arr("profiles")) {
            val type = profile.getString("type")
            tally.check("profiles", type, constraintProfileDigest(ConstraintProfileDescriptor(profile.getString("profile"), type)) ==
                profile.getString("profile_digest"))
            for (item in profile.arr("cases")) {
                cases++
                val params = if (item.optBoolean("params_absent")) null else {
                    val wrapped = JSONArray().put(item.get("params")).toString()
                    wrapped.substring(1, wrapped.length - 1).toByteArray(Charsets.UTF_8)
                }
                val input = ConstraintEvaluationInput(type, params,
                    context = context(item.optJSONObject("context") ?: JSONObject()))
                val result = if (type.endsWith("max_count")) evaluateMaxCount(input) else evaluateAllowedValues(input)
                tally.check("cases", "$type/${item.getString("name")}", result.outcome.name.lowercase() == item.getString("outcome")) { result.outcome.name }
            }
        }
        for (item in corpus.arr("context_bounds")) {
            val actual = classOf { validateRequestContext(context(item.getJSONObject("context"))) }
            tally.check("bounds", item.getString("name"), actual == item.optString("error_class", "ok")) { actual }
        }
        tally.finish(listOf("profiles" to corpus.arr("profiles").size,
            "cases" to cases, "bounds" to corpus.arr("context_bounds").size))
    }
}
