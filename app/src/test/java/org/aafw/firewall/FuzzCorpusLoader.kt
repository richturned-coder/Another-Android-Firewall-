package org.aafw.firewall

object FuzzCorpusLoader {
    fun loadHexResource(name: String): ByteArray {
        val stream = requireNotNull(
            FuzzCorpusLoader::class.java.classLoader?.getResourceAsStream("fuzz-corpus/$name")
        ) { "Missing fuzz corpus resource: fuzz-corpus/$name" }
        val text = stream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        val hexTokens = text.lineSequence()
            .map { it.substringBefore('#').trim() }
            .filter { it.isNotEmpty() }
            .flatMap { it.split(Regex("\\s+")).asSequence() }
            .filter { it.isNotEmpty() }
            .toList()
        return ByteArray(hexTokens.size) { i -> hexTokens[i].toInt(16).toByte() }
    }
}
