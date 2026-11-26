package org.aafw.firewall.data.local

import kotlinx.coroutines.flow.Flow

class FirewallRepository(
    private val ruleDao: FirewallRuleDao,
    private val alertDao: IdsAlertDao,
    private val threatFeedDao: ThreatFeedDao,
    private val captureSessionDao: CaptureSessionDao,
    private val rfAllocationDao: RfAllocationDao
) {
    val allRules: Flow<List<FirewallRuleEntity>> = ruleDao.observeAllRules()
    val recentAlerts: Flow<List<IdsAlertEntity>> = alertDao.observeRecentAlerts()
    val alertCount: Flow<Int> = alertDao.observeAlertCount()
    val threatFeedEntries: Flow<List<ThreatFeedEntryEntity>> = threatFeedDao.observeAllEntries()
    val captureSessions: Flow<List<CaptureSessionEntity>> = captureSessionDao.observeAllSessions()
    val rfAllocations: Flow<List<RfAllocationEntity>> = rfAllocationDao.observeAllAllocations()

    suspend fun ensureSeeded() {
        if (threatFeedDao.count() == 0) {
            threatFeedDao.insertAll(SeedDatabaseCatalog.defaultThreatIndicators())
        }
        if (rfAllocationDao.count() == 0) {
            rfAllocationDao.insertAll(SeedDatabaseCatalog.defaultRfAllocations())
        }
    }

    suspend fun getActiveRulesSnapshot(): List<FirewallRuleEntity> =
        ruleDao.getActiveRulesSnapshot()

    suspend fun upsertRule(rule: FirewallRuleEntity): Long = ruleDao.upsertRule(rule)

    suspend fun deleteRule(id: Long) = ruleDao.deleteRuleById(id)

    suspend fun deleteRuleByTarget(ruleType: RuleType, targetValue: String) =
        ruleDao.deleteByTarget(ruleType.name, targetValue)

    suspend fun incrementRuleHit(ruleType: RuleType, targetValue: String) =
        ruleDao.incrementHitCount(ruleType.name, targetValue)

    suspend fun incrementRuleHitBy(ruleType: RuleType, targetValue: String, delta: Long) {
        if (delta > 0L) ruleDao.incrementHitCountBy(ruleType.name, targetValue, delta)
    }

    suspend fun insertAlert(alert: IdsAlertEntity): Long = alertDao.insertAlert(alert)

    suspend fun clearAlerts() = alertDao.clearAllAlerts()

    suspend fun deleteAlert(id: Long) = alertDao.deleteAlertById(id)

    suspend fun getEnabledThreatIndicators(): List<String> = threatFeedDao.getEnabledIndicators()

    suspend fun addThreatIndicators(entries: List<ThreatFeedEntryEntity>) =
        threatFeedDao.insertAll(entries)

    suspend fun toggleThreatIndicator(id: Long, enabled: Boolean) =
        threatFeedDao.setEnabled(id, enabled)

    suspend fun deleteThreatIndicator(id: Long) = threatFeedDao.deleteById(id)

    suspend fun insertCaptureSession(session: CaptureSessionEntity): Long =
        captureSessionDao.insertSession(session)

    suspend fun updateCaptureStats(
        id: Long,
        endedAt: Long?,
        packetCount: Long,
        byteCount: Long,
        droppedCount: Long
    ) = captureSessionDao.updateSessionStats(id, endedAt, packetCount, byteCount, droppedCount)

    suspend fun deleteCaptureSession(id: Long) = captureSessionDao.deleteSessionById(id)

    suspend fun lookupRfBand(freqMhz: Double): List<RfAllocationEntity> =
        rfAllocationDao.lookupFrequency(freqMhz)
}
