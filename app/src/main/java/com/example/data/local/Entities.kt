package com.example.data.local

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

enum class RuleType {
    APP_UID,
    IP_CIDR,
    PORT,
    DOMAIN
}

enum class RuleAction {
    ALLOW,
    BLOCK
}

enum class AlertSeverity(val weight: Int) {
    CRITICAL(4),
    HIGH(3),
    MEDIUM(2),
    LOW(1)
}

enum class AlertCategory {
    PHISHING_FEED,
    HOMOGRAPH_IDN,
    DGA_ENTROPY,
    PORT_SCAN,
    FUZZING_BURST,
    MALFORMED_SPIKE,
    SQL_INJECTION,
    COMMAND_INJECTION,
    XSS_INJECTION,
    PATH_TRAVERSAL
}

@Entity(
    tableName = "firewall_rules",
    indices = [Index(value = ["ruleType", "targetValue"], unique = true)]
)
data class FirewallRuleEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val ruleType: String, // RuleType.name
    val targetValue: String, // UID as string, IP/CIDR, port or proto:port, or domain suffix
    val displayLabel: String, // App name or user label
    val packageName: String? = null,
    val action: String, // RuleAction.name
    val enabled: Boolean = true,
    val hitCount: Long = 0L,
    val createdAt: Long = System.currentTimeMillis()
)

@Entity(
    tableName = "ids_alerts",
    indices = [Index(value = ["timestamp"]), Index(value = ["severity"])]
)
data class IdsAlertEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val timestamp: Long = System.currentTimeMillis(),
    val severity: String, // AlertSeverity.name
    val category: String, // AlertCategory.name
    val ruleId: String,
    val title: String,
    val description: String,
    val appUid: Int,
    val appLabel: String,
    val protocol: String,
    val srcEndpoint: String,
    val dstEndpoint: String,
    val domainOrSni: String?,
    val inspectionLayer: String, // CLEARTEXT_DPI | TLS_METADATA | BEHAVIORAL
    val payloadExcerpt: String
)

@Entity(
    tableName = "threat_feed_entries",
    indices = [Index(value = ["indicator"], unique = true)]
)
data class ThreatFeedEntryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val indicator: String, // lowercased domain or host suffix
    val source: String, // OpenPhish-Local, URLhaus-Local, PhishTank-Local, Custom-SAF
    val category: String, // PHISHING, MALWARE_C2, SCAM
    val enabled: Boolean = true,
    val addedAt: Long = System.currentTimeMillis()
)

@Entity(
    tableName = "capture_sessions",
    indices = [Index(value = ["startedAt"])]
)
data class CaptureSessionEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val fileName: String,
    val filePath: String,
    val startedAt: Long,
    val endedAt: Long? = null,
    val packetCount: Long = 0L,
    val byteCount: Long = 0L,
    val droppedCount: Long = 0L
)

@Entity(
    tableName = "rf_allocations",
    indices = [Index(value = ["startFreqMhz", "endFreqMhz"])]
)
data class RfAllocationEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val startFreqMhz: Double,
    val endFreqMhz: Double,
    val bandName: String,
    val serviceCategory: String,
    val commonProtocols: String,
    val typicalModulation: String
)
