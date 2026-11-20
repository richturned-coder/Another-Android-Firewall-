package com.example.engine.network

import com.example.data.local.AlertCategory
import com.example.data.local.AlertSeverity
import com.example.data.local.IdsAlertEntity
import java.net.URLDecoder
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.ln

data class IdsConfig(
    val dnsPhishingEnabled: Boolean = true,
    val heuristicsEnabled: Boolean = true,
    val behavioralScanEnabled: Boolean = true,
    val httpDpiEnabled: Boolean = true
)

private data class DpiSignature(
    val ruleId: String,
    val keyword: String,
    val category: AlertCategory,
    val severity: AlertSeverity,
    val title: String,
    val confirmRegex: Regex
)

/**
 * Compact Aho-Corasick multi-pattern automaton for fast single-pass HTTP DPI scanning.
 */
private class AhoCorasickMatcher(signatures: List<DpiSignature>) {
    private class Node {
        val next = HashMap<Char, Int>()
        var fail: Int = 0
        val outputs = ArrayList<DpiSignature>()
    }

    private val nodes = ArrayList<Node>().apply { add(Node()) }

    init {
        for (sig in signatures) {
            var cur = 0
            for (ch in sig.keyword.lowercase()) {
                val nxt = nodes[cur].next[ch]
                if (nxt == null) {
                    val created = nodes.size
                    nodes.add(Node())
                    nodes[cur].next[ch] = created
                    cur = created
                } else {
                    cur = nxt
                }
            }
            nodes[cur].outputs.add(sig)
        }
        buildFailureLinks()
    }

    private fun buildFailureLinks() {
        val queue = ArrayDeque<Int>()
        for (child in nodes[0].next.values) {
            nodes[child].fail = 0
            queue.add(child)
        }
        while (queue.isNotEmpty()) {
            val cur = queue.removeFirst()
            for ((ch, nxt) in nodes[cur].next) {
                var f = nodes[cur].fail
                while (f != 0 && !nodes[f].next.containsKey(ch)) {
                    f = nodes[f].fail
                }
                val target = nodes[f].next[ch] ?: 0
                nodes[nxt].fail = target
                nodes[nxt].outputs.addAll(nodes[target].outputs)
                queue.add(nxt)
            }
        }
    }

    fun scan(lowerText: String): List<DpiSignature> {
        val hits = LinkedHashSet<DpiSignature>()
        var cur = 0
        for (ch in lowerText) {
            while (cur != 0 && !nodes[cur].next.containsKey(ch)) {
                cur = nodes[cur].fail
            }
            cur = nodes[cur].next[ch] ?: 0
            if (nodes[cur].outputs.isNotEmpty()) {
                hits.addAll(nodes[cur].outputs)
            }
        }
        return hits.toList()
    }
}

private class SlidingWindowStats {
    val portTimestamps = ArrayDeque<Pair<Long, Int>>()
    val malformedTimestamps = ArrayDeque<Long>()
    val httpErrorTimestamps = ArrayDeque<Long>()
    var lastAlertedAt: Long = 0L
}

class IdsEngine {
    private val configRef = AtomicReference(IdsConfig())
    private val threatDomainsRef = AtomicReference<Set<String>>(emptySet())
    private val behaviorByKey = ConcurrentHashMap<String, SlidingWindowStats>()

    private val highValueBrands = listOf(
        "paypal", "google", "microsoft", "apple", "amazon", "chase", "wellsfargo", "coinbase", "binance", "github"
    )
    private val suspiciousTlds = setOf("xyz", "top", "icu", "click", "gq", "tk", "ml", "cf", "pw", "zip")

    private val dpiSignatures = listOf(
        // SQL Injection (OWASP CRS 942xxx inspired)
        DpiSignature(
            "CRS-942100", "union select", AlertCategory.SQL_INJECTION, AlertSeverity.CRITICAL,
            "SQL Injection: UNION SELECT Payload",
            Regex("""(?i)union\s+(all\s+)?select\b""")
        ),
        DpiSignature(
            "CRS-942110", "information_schema", AlertCategory.SQL_INJECTION, AlertSeverity.CRITICAL,
            "SQL Injection: Schema Enumeration",
            Regex("""(?i)information_schema\.(tables|columns|schemata)""")
        ),
        DpiSignature(
            "CRS-942120", "or 1=1", AlertCategory.SQL_INJECTION, AlertSeverity.HIGH,
            "SQL Injection: Boolean Tautology",
            Regex("""(?i)('|\s|%27)or\s+1\s*=\s*1""")
        ),
        DpiSignature(
            "CRS-942130", "waitfor delay", AlertCategory.SQL_INJECTION, AlertSeverity.CRITICAL,
            "SQL Injection: Time-Based Blind Probe",
            Regex("""(?i)(waitfor\s+delay|sleep\s*\(\s*\d+\s*\)|pg_sleep\s*\()""")
        ),
        DpiSignature(
            "CRS-942135", "sleep(", AlertCategory.SQL_INJECTION, AlertSeverity.HIGH,
            "SQL Injection: SLEEP() Timing Probe",
            Regex("""(?i)\bsleep\s*\(\s*\d+\s*\)""")
        ),
        // XSS (OWASP CRS 941xxx inspired)
        DpiSignature(
            "CRS-941100", "<script", AlertCategory.XSS_INJECTION, AlertSeverity.HIGH,
            "Cross-Site Scripting: <script> Tag",
            Regex("""(?i)<\s*script[\s>]""")
        ),
        DpiSignature(
            "CRS-941110", "onerror=", AlertCategory.XSS_INJECTION, AlertSeverity.HIGH,
            "Cross-Site Scripting: Event Handler Injection",
            Regex("""(?i)\bon(error|load|mouseover|focus)\s*=""")
        ),
        DpiSignature(
            "CRS-941120", "javascript:", AlertCategory.XSS_INJECTION, AlertSeverity.MEDIUM,
            "Cross-Site Scripting: javascript: URI",
            Regex("""(?i)javascript\s*:""")
        ),
        DpiSignature(
            "CRS-941130", "document.cookie", AlertCategory.XSS_INJECTION, AlertSeverity.HIGH,
            "Cross-Site Scripting: Cookie Exfiltration Attempt",
            Regex("""(?i)document\s*\.\s*cookie""")
        ),
        // Command Injection (OWASP CRS 932xxx inspired)
        DpiSignature(
            "CRS-932100", "/etc/passwd", AlertCategory.COMMAND_INJECTION, AlertSeverity.CRITICAL,
            "OS Command / File Injection: /etc/passwd Access",
            Regex("""(?i)(;\s*cat|\|\s*cat|\.\./).*?/etc/passwd""")
        ),
        DpiSignature(
            "CRS-932110", "; cat ", AlertCategory.COMMAND_INJECTION, AlertSeverity.CRITICAL,
            "OS Command Injection: Chained Shell Command",
            Regex("""(?i)(;|\||&&)\s*(cat|id|whoami|uname|wget|curl|nc|bash|sh)\b""")
        ),
        DpiSignature(
            "CRS-932120", "| bash", AlertCategory.COMMAND_INJECTION, AlertSeverity.CRITICAL,
            "OS Command Injection: Pipe to Shell",
            Regex("""(?i)\|\s*(/bin/)?(ba)?sh\b""")
        ),
        DpiSignature(
            "CRS-932130", "$(whoami)", AlertCategory.COMMAND_INJECTION, AlertSeverity.CRITICAL,
            "OS Command Injection: Subshell Execution",
            Regex("""(?i)\$\((whoami|id|cat|uname|sh|bash)[^)]*\)""")
        ),
        // Path Traversal (OWASP CRS 930xxx)
        DpiSignature(
            "CRS-930100", "../", AlertCategory.PATH_TRAVERSAL, AlertSeverity.HIGH,
            "Path Traversal: Directory Escape Sequence",
            Regex("""(\.\./){2,}|(\.\.\\){2,}""")
        )
    )

    private val matcher = AhoCorasickMatcher(dpiSignatures)

    fun updateConfig(config: IdsConfig) {
        configRef.set(config)
    }

    fun updateThreatFeed(domains: Collection<String>) {
        threatDomainsRef.set(domains.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet())
    }

    fun inspect(packet: ParsedPacket, appUid: Int, appLabel: String): List<IdsAlertEntity> {
        val cfg = configRef.get()
        val alerts = ArrayList<IdsAlertEntity>()
        val now = System.currentTimeMillis()
        val srcEp = "${packet.srcIp}:${packet.srcPort}"
        val dstEp = "${packet.dstIp}:${packet.dstPort}"

        // 1. DNS & TLS SNI Phishing + Heuristic Checks
        val host = packet.dnsQueryDomain ?: packet.tlsInfo?.sniHost ?: packet.httpInfo?.hostHeader
        val layer = when {
            packet.tlsInfo != null -> "TLS_METADATA"
            packet.httpInfo != null -> "CLEARTEXT_DPI"
            else -> "DNS_METADATA"
        }

        if (host != null) {
            if (cfg.dnsPhishingEnabled && matchesThreatFeed(host)) {
                alerts.add(
                    IdsAlertEntity(
                        timestamp = now,
                        severity = AlertSeverity.CRITICAL.name,
                        category = AlertCategory.PHISHING_FEED.name,
                        ruleId = "IDS-FEED-001",
                        title = "Threat Feed Match: $host",
                        description = "Hostname matched local on-device phishing/malware indicator feed." +
                            (packet.tlsInfo?.let { " [${it.tlsVersionLabel} JA3=${it.ja3Hash.take(12)}]" } ?: ""),
                        appUid = appUid,
                        appLabel = appLabel,
                        protocol = packet.protocol.label,
                        srcEndpoint = srcEp,
                        dstEndpoint = dstEp,
                        domainOrSni = host,
                        inspectionLayer = layer,
                        payloadExcerpt = buildHostExcerpt(packet, host)
                    )
                )
            }
            if (cfg.heuristicsEnabled) {
                evaluateDomainHeuristics(host, packet, appUid, appLabel, srcEp, dstEp, layer, now)?.let {
                    alerts.add(it)
                }
            }
        }

        // 2. Behavioral Fuzzing / Port Scanning / Malformed Packet Spikes
        if (cfg.behavioralScanEnabled) {
            evaluateBehavior(packet, appUid, appLabel, srcEp, dstEp, now)?.let {
                alerts.add(it)
            }
        }

        // 3. HTTP Deep Packet Inspection (Aho-Corasick + Regex across URL, Query Params, Headers, Body)
        if (cfg.httpDpiEnabled && packet.httpInfo != null && packet.httpInfo.isRequest) {
            val rawText = packet.httpInfo.inspectableText
            val decoded = runCatching { URLDecoder.decode(rawText.replace("+", "%2B"), "UTF-8") }
                .getOrDefault(rawText)
            val lowerDecoded = decoded.lowercase()
            val candidates = matcher.scan(lowerDecoded)
            for (sig in candidates) {
                if (sig.confirmRegex.containsMatchIn(decoded)) {
                    alerts.add(
                        IdsAlertEntity(
                            timestamp = now,
                            severity = sig.severity.name,
                            category = sig.category.name,
                            ruleId = sig.ruleId,
                            title = sig.title,
                            description = "Matched ${sig.ruleId} in HTTP ${packet.httpInfo.method ?: "REQ"} ${packet.httpInfo.rawTarget ?: ""}",
                            appUid = appUid,
                            appLabel = appLabel,
                            protocol = "HTTP",
                            srcEndpoint = srcEp,
                            dstEndpoint = dstEp,
                            domainOrSni = host,
                            inspectionLayer = "CLEARTEXT_DPI",
                            payloadExcerpt = decoded.take(280).replace('\r', ' ').replace('\n', ' ')
                        )
                    )
                    break // Report highest-confidence hit per packet to avoid alert storm
                }
            }
        }

        return alerts
    }

    private fun matchesThreatFeed(host: String): Boolean {
        val feed = threatDomainsRef.get()
        if (feed.isEmpty()) return false
        if (feed.contains(host)) return true
        var idx = host.indexOf('.')
        while (idx != -1 && idx + 1 < host.length) {
            if (feed.contains(host.substring(idx + 1))) return true
            idx = host.indexOf('.', idx + 1)
        }
        return false
    }

    private fun evaluateDomainHeuristics(
        host: String,
        packet: ParsedPacket,
        appUid: Int,
        appLabel: String,
        srcEp: String,
        dstEp: String,
        layer: String,
        now: Long
    ): IdsAlertEntity? {
        val labels = host.split('.').filter { it.isNotEmpty() }
        if (labels.size < 2) return null

        // Punycode / IDN Homograph check
        if (labels.any { it.startsWith("xn--") }) {
            return IdsAlertEntity(
                timestamp = now,
                severity = AlertSeverity.HIGH.name,
                category = AlertCategory.HOMOGRAPH_IDN.name,
                ruleId = "IDS-HEUR-IDN",
                title = "Punycode / Homograph Domain Detected",
                description = "Internationalized domain ($host) uses xn-- punycode encoding frequently abused in lookalike phishing.",
                appUid = appUid,
                appLabel = appLabel,
                protocol = packet.protocol.label,
                srcEndpoint = srcEp,
                dstEndpoint = dstEp,
                domainOrSni = host,
                inspectionLayer = layer,
                payloadExcerpt = buildHostExcerpt(packet, host)
            )
        }

        // Brand typosquatting + suspicious TLD
        val tld = labels.last()
        val sld = labels[labels.size - 2]
        val normalizedSld = sld.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's')
        for (brand in highValueBrands) {
            val dist = levenshtein(normalizedSld, brand)
            if ((dist in 1..2 && sld.length >= 5) || (normalizedSld.contains(brand) && tld in suspiciousTlds && sld != brand)) {
                return IdsAlertEntity(
                    timestamp = now,
                    severity = AlertSeverity.HIGH.name,
                    category = AlertCategory.HOMOGRAPH_IDN.name,
                    ruleId = "IDS-HEUR-BRAND",
                    title = "Suspected Brand Impersonation ($brand)",
                    description = "Domain $host closely resembles '$brand' (edit distance=$dist, TLD=.$tld).",
                    appUid = appUid,
                    appLabel = appLabel,
                    protocol = packet.protocol.label,
                    srcEndpoint = srcEp,
                    dstEndpoint = dstEp,
                    domainOrSni = host,
                    inspectionLayer = layer,
                    payloadExcerpt = buildHostExcerpt(packet, host)
                )
            }
        }

        // High Shannon entropy DGA / DNS tunneling label check
        val longestLabel = labels.maxByOrNull { it.length } ?: ""
        if (longestLabel.length >= 18) {
            val entropy = shannonEntropy(longestLabel)
            if (entropy >= 3.85) {
                return IdsAlertEntity(
                    timestamp = now,
                    severity = AlertSeverity.MEDIUM.name,
                    category = AlertCategory.DGA_ENTROPY.name,
                    ruleId = "IDS-HEUR-DGA",
                    title = "High-Entropy / Possible DGA or DNS Tunnel",
                    description = "Label '${longestLabel.take(24)}...' has Shannon entropy ${"%.2f".format(entropy)} bits (len=${longestLabel.length}).",
                    appUid = appUid,
                    appLabel = appLabel,
                    protocol = packet.protocol.label,
                    srcEndpoint = srcEp,
                    dstEndpoint = dstEp,
                    domainOrSni = host,
                    inspectionLayer = layer,
                    payloadExcerpt = buildHostExcerpt(packet, host)
                )
            }
        }
        return null
    }

    private fun evaluateBehavior(
        packet: ParsedPacket,
        appUid: Int,
        appLabel: String,
        srcEp: String,
        dstEp: String,
        now: Long
    ): IdsAlertEntity? {
        val windowMs = 10_000L
        val cooldownMs = 15_000L
        val key = "$appUid:${packet.dstIp}"
        val stats = behaviorByKey.computeIfAbsent(key) { SlidingWindowStats() }

        synchronized(stats) {
            // Trim sliding window
            while (stats.portTimestamps.isNotEmpty() && now - stats.portTimestamps.first().first > windowMs) {
                stats.portTimestamps.removeFirst()
            }
            while (stats.malformedTimestamps.isNotEmpty() && now - stats.malformedTimestamps.first() > windowMs) {
                stats.malformedTimestamps.removeFirst()
            }
            while (stats.httpErrorTimestamps.isNotEmpty() && now - stats.httpErrorTimestamps.first() > windowMs) {
                stats.httpErrorTimestamps.removeFirst()
            }

            if (packet.isMalformed) {
                stats.malformedTimestamps.addLast(now)
                if (stats.malformedTimestamps.size >= 8 && now - stats.lastAlertedAt > cooldownMs) {
                    stats.lastAlertedAt = now
                    return IdsAlertEntity(
                        timestamp = now,
                        severity = AlertSeverity.HIGH.name,
                        category = AlertCategory.MALFORMED_SPIKE.name,
                        ruleId = "IDS-BEHAV-MALF",
                        title = "Malformed Packet Spike Detected",
                        description = "${stats.malformedTimestamps.size} malformed/truncated packets observed in 10s window.",
                        appUid = appUid,
                        appLabel = appLabel,
                        protocol = packet.protocol.label,
                        srcEndpoint = srcEp,
                        dstEndpoint = dstEp,
                        domainOrSni = packet.domainOrSni,
                        inspectionLayer = "BEHAVIORAL",
                        payloadExcerpt = "TotalLen=${packet.totalLength} IPv${packet.ipVersion} Proto=${packet.protocol.label}"
                    )
                }
            }

            if (packet.dstPort > 0 && (packet.isTcpSyn || packet.protocol == TransportProtocol.UDP)) {
                stats.portTimestamps.addLast(now to packet.dstPort)
                val distinctPorts = stats.portTimestamps.map { it.second }.toSet()
                if (distinctPorts.size >= 10 && now - stats.lastAlertedAt > cooldownMs) {
                    stats.lastAlertedAt = now
                    return IdsAlertEntity(
                        timestamp = now,
                        severity = AlertSeverity.HIGH.name,
                        category = AlertCategory.PORT_SCAN.name,
                        ruleId = "IDS-BEHAV-SCAN",
                        title = "Rapid Port Scan / Probe Burst",
                        description = "Probed ${distinctPorts.size} distinct ports on ${packet.dstIp} within 10 seconds.",
                        appUid = appUid,
                        appLabel = appLabel,
                        protocol = packet.protocol.label,
                        srcEndpoint = srcEp,
                        dstEndpoint = dstEp,
                        domainOrSni = null,
                        inspectionLayer = "BEHAVIORAL",
                        payloadExcerpt = "Ports: ${distinctPorts.sorted().take(12).joinToString(", ")}"
                    )
                }
            }

            val statusCode = packet.httpInfo?.statusCode
            if (statusCode != null && statusCode in setOf(400, 403, 404, 500)) {
                stats.httpErrorTimestamps.addLast(now)
                if (stats.httpErrorTimestamps.size >= 12 && now - stats.lastAlertedAt > cooldownMs) {
                    stats.lastAlertedAt = now
                    return IdsAlertEntity(
                        timestamp = now,
                        severity = AlertSeverity.MEDIUM.name,
                        category = AlertCategory.FUZZING_BURST.name,
                        ruleId = "IDS-BEHAV-FUZZ",
                        title = "HTTP Fuzzing / Error Response Burst",
                        description = "${stats.httpErrorTimestamps.size} HTTP 4xx/5xx error responses within 10s (latest: HTTP $statusCode).",
                        appUid = appUid,
                        appLabel = appLabel,
                        protocol = "HTTP",
                        srcEndpoint = srcEp,
                        dstEndpoint = dstEp,
                        domainOrSni = packet.domainOrSni,
                        inspectionLayer = "BEHAVIORAL",
                        payloadExcerpt = "Latest response HTTP $statusCode from ${packet.srcIp}"
                    )
                }
            }
        }
        return null
    }

    private fun buildHostExcerpt(packet: ParsedPacket, host: String): String = buildString {
        append("HOST=").append(host)
        packet.tlsInfo?.let {
            append(" | ").append(it.tlsVersionLabel)
            append(" | JA3=").append(it.ja3Hash)
        }
    }

    private fun shannonEntropy(input: String): Double {
        if (input.isEmpty()) return 0.0
        val counts = HashMap<Char, Int>()
        for (c in input) counts[c] = (counts[c] ?: 0) + 1
        val len = input.length.toDouble()
        var entropy = 0.0
        for (count in counts.values) {
            val p = count / len
            entropy -= p * (ln(p) / ln(2.0))
        }
        return entropy
    }

    private fun levenshtein(a: String, b: String): Int {
        if (a == b) return 0
        if (a.isEmpty()) return b.length
        if (b.isEmpty()) return a.length
        var prev = IntArray(b.length + 1) { it }
        var curr = IntArray(b.length + 1)
        for (i in 1..a.length) {
            curr[0] = i
            for (j in 1..b.length) {
                val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                curr[j] = minOf(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            }
            val tmp = prev
            prev = curr
            curr = tmp
        }
        return prev[b.length]
    }
}
