package com.ratifyprotocol

object CorpusReadmeVectors {
    fun run() {
        val text = String(Corpus.bytes("README.md"), Charsets.UTF_8)
        val files = Corpus.list("v2").filter { it.endsWith(".json") }
        val tally = Tally("README.md")
        for (file in files) {
            tally.check("files", file, text.contains("`$file`")) { "missing corpus file" }
        }
        for (section in listOf("# Protocol v2 test vectors", "## cross-sdk/", "## provider-evidence/")) {
            tally.check("sections", section, text.contains(section)) { "missing corpus section" }
        }
        tally.check("script", "derive-external-mu.py", text.contains("derive-external-mu.py")) {
            "missing generator script"
        }
        tally.finish(listOf("files" to files.size, "sections" to 3, "script" to 1))
    }
}
