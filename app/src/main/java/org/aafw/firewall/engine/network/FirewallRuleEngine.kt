package org.aafw.firewall.engine.network

import org.aafw.firewall.data.local.FirewallRuleEntity
import org.aafw.firewall.data.local.RuleAction
import org.aafw.firewall.data.local.RuleType
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicReference

data class FirewallVerdict(
    val allowed: Boolean,
    val matchedRuleType: RuleType?,
    val matchedTarget: String?,
    val reason: String
)

private data class CidrRule(
    val rawTarget: String,
    val networkBytes: ByteArray,
    val prefixLength: Int,
    val action: RuleAction
)

private data class RuleSnapshot(
    val rulesLoaded: Boolean,
    val defaultBlockAll: Boolean,
    val appRules: Map<Int, RuleAction>,
    val exactIpRules: Map<String, RuleAction>,
    val cidrRules: List<CidrRule>,
    val portRules: Map<String, RuleAction>, // "443", "TCP:443", "UDP:53"
    val domainRules: Map<String, RuleAction>
)

class FirewallRuleEngine(
    private val failClosedUntilRulesLoaded: Boolean = false
) {
    private val snapshotRef = AtomicReference(
        RuleSnapshot(
            rulesLoaded = false,
            defaultBlockAll = false,
            appRules = emptyMap(),
            exactIpRules = emptyMap(),
            cidrRules = emptyList(),
            portRules = emptyMap(),
            domainRules = emptyMap()
        )
    )

    fun isRulesLoaded(): Boolean = snapshotRef.get().rulesLoaded

    fun updateRules(rules: List<FirewallRuleEntity>, defaultBlockAll: Boolean) {
        val appMap = HashMap<Int, RuleAction>()
        val exactIps = HashMap<String, RuleAction>()
        val cidrs = ArrayList<CidrRule>()
        val ports = HashMap<String, RuleAction>()
        val domains = HashMap<String, RuleAction>()

        for (rule in rules) {
            if (!rule.enabled) continue
            val action = runCatching { RuleAction.valueOf(rule.action) }.getOrNull() ?: continue
            val type = runCatching { RuleType.valueOf(rule.ruleType) }.getOrNull() ?: continue
            val target = rule.targetValue.trim()

            when (type) {
                RuleType.APP_UID -> target.toIntOrNull()?.let { appMap[it] = action }
                RuleType.IP_CIDR -> {
                    if (target.contains('/')) {
                        parseCidr(target, action)?.let { cidrs.add(it) }
                    } else {
                        exactIps[target.lowercase()] = action
                    }
                }
                RuleType.PORT -> ports[target.uppercase()] = action
                RuleType.DOMAIN -> domains[target.lowercase().trimStart('.')] = action
            }
        }

        snapshotRef.set(
            RuleSnapshot(
                rulesLoaded = true,
                defaultBlockAll = defaultBlockAll,
                appRules = appMap,
                exactIpRules = exactIps,
                cidrRules = cidrs,
                portRules = ports,
                domainRules = domains
            )
        )
    }

    fun evaluate(packet: ParsedPacket, appUid: Int): FirewallVerdict {
        if (packet.isMalformed) {
            return FirewallVerdict(
                allowed = false,
                matchedRuleType = null,
                matchedTarget = null,
                reason = "Malformed packet dropped (fail-closed)"
            )
        }

        val snap = snapshotRef.get()
        if (failClosedUntilRulesLoaded && !snap.rulesLoaded) {
            return FirewallVerdict(
                allowed = false,
                matchedRuleType = null,
                matchedTarget = null,
                reason = "Rules initializing (fail-closed)"
            )
        }

        // 1. Explicit Domain / SNI rule (most specific indicator)
        val host = packet.domainOrSni?.lowercase()
        if (host != null && snap.domainRules.isNotEmpty()) {
            val matchedDomain = matchDomainSuffix(host, snap.domainRules)
            if (matchedDomain != null) {
                val (domainKey, action) = matchedDomain
                return FirewallVerdict(
                    allowed = action == RuleAction.ALLOW,
                    matchedRuleType = RuleType.DOMAIN,
                    matchedTarget = domainKey,
                    reason = "Domain rule: $domainKey (${action.name})"
                )
            }
        }

        // 2. Explicit IP or CIDR rule
        val dstIpLower = packet.dstIp.lowercase()
        snap.exactIpRules[dstIpLower]?.let { action ->
            return FirewallVerdict(
                allowed = action == RuleAction.ALLOW,
                matchedRuleType = RuleType.IP_CIDR,
                matchedTarget = dstIpLower,
                reason = "IP rule: $dstIpLower (${action.name})"
            )
        }
        for (cidr in snap.cidrRules) {
            if (matchesCidr(packet.dstIpBytes, cidr.networkBytes, cidr.prefixLength)) {
                return FirewallVerdict(
                    allowed = cidr.action == RuleAction.ALLOW,
                    matchedRuleType = RuleType.IP_CIDR,
                    matchedTarget = cidr.rawTarget,
                    reason = "CIDR rule: ${cidr.rawTarget} (${cidr.action.name})"
                )
            }
        }

        // 3. Explicit Port rule (proto:port or bare port)
        if (packet.dstPort > 0 && snap.portRules.isNotEmpty()) {
            val protoKey = "${packet.protocol.label.uppercase()}:${packet.dstPort}"
            val portKey = packet.dstPort.toString()
            val portAction = snap.portRules[protoKey] ?: snap.portRules[portKey]
            val matchedKey = if (snap.portRules.containsKey(protoKey)) protoKey else portKey
            if (portAction != null) {
                return FirewallVerdict(
                    allowed = portAction == RuleAction.ALLOW,
                    matchedRuleType = RuleType.PORT,
                    matchedTarget = matchedKey,
                    reason = "Port rule: $matchedKey (${portAction.name})"
                )
            }
        }

        // 4. AFWall+ Per-App UID rule
        if (appUid >= 0) {
            snap.appRules[appUid]?.let { action ->
                return FirewallVerdict(
                    allowed = action == RuleAction.ALLOW,
                    matchedRuleType = RuleType.APP_UID,
                    matchedTarget = appUid.toString(),
                    reason = "App UID $appUid rule (${action.name})"
                )
            }
        }

        // 5. Fallback to Global Default Posture (Denylist vs Allowlist)
        val allowByDefault = !snap.defaultBlockAll
        val fallbackReason = when {
            allowByDefault -> "Default Allow (Denylist)"
            appUid < 0 -> "Unattributed UID blocked (AFWall+ Allowlist fail-closed)"
            else -> "Default Block (AFWall+ Allowlist)"
        }
        return FirewallVerdict(
            allowed = allowByDefault,
            matchedRuleType = null,
            matchedTarget = null,
            reason = fallbackReason
        )
    }

    private fun matchDomainSuffix(host: String, domainRules: Map<String, RuleAction>): Pair<String, RuleAction>? {
        domainRules[host]?.let { return host to it }
        var dotIndex = host.indexOf('.')
        while (dotIndex != -1 && dotIndex + 1 < host.length) {
            val suffix = host.substring(dotIndex + 1)
            domainRules[suffix]?.let { return suffix to it }
            dotIndex = host.indexOf('.', dotIndex + 1)
        }
        return null
    }

    private fun parseCidr(cidr: String, action: RuleAction): CidrRule? {
        val parts = cidr.split('/')
        if (parts.size != 2) return null
        val prefix = parts[1].toIntOrNull() ?: return null
        val bytes = runCatching { InetAddress.getByName(parts[0]).address }.getOrNull() ?: return null
        val maxBits = bytes.size * 8
        if (prefix < 0 || prefix > maxBits) return null
        return CidrRule(cidr, bytes, prefix, action)
    }

    private fun matchesCidr(targetBytes: ByteArray, netBytes: ByteArray, prefixBits: Int): Boolean {
        if (targetBytes.size != netBytes.size) return false
        val fullBytes = prefixBits / 8
        val remBits = prefixBits % 8
        for (i in 0 until fullBytes) {
            if (targetBytes[i] != netBytes[i]) return false
        }
        if (remBits > 0) {
            val mask = (0xFF shl (8 - remBits)) and 0xFF
            if ((targetBytes[fullBytes].toInt() and mask) != (netBytes[fullBytes].toInt() and mask)) {
                return false
            }
        }
        return true
    }
}
