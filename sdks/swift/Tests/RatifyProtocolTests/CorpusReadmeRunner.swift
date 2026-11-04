import Foundation

enum CorpusReadmeRunner {
    static func run() throws {
        let text = try String(contentsOf: Corpus.url("README.md"), encoding: .utf8)
        let files = try FileManager.default.contentsOfDirectory(atPath: Corpus.dir.path)
            .filter { $0.hasSuffix(".json") }
        let tally = Tally("README.md")
        for file in files {
            tally.check("files", file, text.contains("`\(file)`"), "missing corpus file")
        }
        for section in ["# Protocol v2 test vectors", "## cross-sdk/", "## provider-evidence/"] {
            tally.check("sections", section, text.contains(section), "missing corpus section")
        }
        tally.check("script", "derive-external-mu.py", text.contains("derive-external-mu.py"),
                    "missing generator script")
        tally.finish([("files", files.count), ("sections", 3), ("script", 1)])
    }
}
