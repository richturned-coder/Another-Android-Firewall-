package org.aafw.firewall.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface FirewallRuleDao {
    @Query("SELECT * FROM firewall_rules ORDER BY createdAt DESC")
    fun observeAllRules(): Flow<List<FirewallRuleEntity>>

    @Query("SELECT * FROM firewall_rules WHERE enabled = 1")
    suspend fun getActiveRulesSnapshot(): List<FirewallRuleEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertRule(rule: FirewallRuleEntity): Long

    @Query("UPDATE firewall_rules SET action = :action, enabled = :enabled WHERE id = :id")
    suspend fun updateRuleState(id: Long, action: String, enabled: Boolean)

    @Query("UPDATE firewall_rules SET hitCount = hitCount + 1 WHERE ruleType = :ruleType AND targetValue = :targetValue")
    suspend fun incrementHitCount(ruleType: String, targetValue: String)

    @Query("UPDATE firewall_rules SET hitCount = hitCount + :delta WHERE ruleType = :ruleType AND targetValue = :targetValue")
    suspend fun incrementHitCountBy(ruleType: String, targetValue: String, delta: Long)

    @Query("DELETE FROM firewall_rules WHERE id = :id")
    suspend fun deleteRuleById(id: Long)

    @Query("DELETE FROM firewall_rules WHERE ruleType = :ruleType AND targetValue = :targetValue")
    suspend fun deleteByTarget(ruleType: String, targetValue: String)
}

@Dao
interface IdsAlertDao {
    @Query("SELECT * FROM ids_alerts ORDER BY timestamp DESC LIMIT 500")
    fun observeRecentAlerts(): Flow<List<IdsAlertEntity>>

    @Query("SELECT COUNT(*) FROM ids_alerts")
    fun observeAlertCount(): Flow<Int>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAlert(alert: IdsAlertEntity): Long

    @Query("DELETE FROM ids_alerts")
    suspend fun clearAllAlerts()

    @Query("DELETE FROM ids_alerts WHERE id = :id")
    suspend fun deleteAlertById(id: Long)
}

@Dao
interface ThreatFeedDao {
    @Query("SELECT * FROM threat_feed_entries ORDER BY addedAt DESC")
    fun observeAllEntries(): Flow<List<ThreatFeedEntryEntity>>

    @Query("SELECT indicator FROM threat_feed_entries WHERE enabled = 1")
    suspend fun getEnabledIndicators(): List<String>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAll(entries: List<ThreatFeedEntryEntity>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entry: ThreatFeedEntryEntity)

    @Query("UPDATE threat_feed_entries SET enabled = :enabled WHERE id = :id")
    suspend fun setEnabled(id: Long, enabled: Boolean)

    @Query("DELETE FROM threat_feed_entries WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("SELECT COUNT(*) FROM threat_feed_entries")
    suspend fun count(): Int
}

@Dao
interface CaptureSessionDao {
    @Query("SELECT * FROM capture_sessions ORDER BY startedAt DESC")
    fun observeAllSessions(): Flow<List<CaptureSessionEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSession(session: CaptureSessionEntity): Long

    @Query(
        "UPDATE capture_sessions SET endedAt = :endedAt, packetCount = :packetCount, " +
            "byteCount = :byteCount, droppedCount = :droppedCount WHERE id = :id"
    )
    suspend fun updateSessionStats(
        id: Long,
        endedAt: Long?,
        packetCount: Long,
        byteCount: Long,
        droppedCount: Long
    )

    @Query("DELETE FROM capture_sessions WHERE id = :id")
    suspend fun deleteSessionById(id: Long)
}

@Dao
interface RfAllocationDao {
    @Query("SELECT * FROM rf_allocations ORDER BY startFreqMhz ASC")
    fun observeAllAllocations(): Flow<List<RfAllocationEntity>>

    @Query("SELECT * FROM rf_allocations WHERE :freqMhz >= startFreqMhz AND :freqMhz <= endFreqMhz")
    suspend fun lookupFrequency(freqMhz: Double): List<RfAllocationEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(allocations: List<RfAllocationEntity>)

    @Query("SELECT COUNT(*) FROM rf_allocations")
    suspend fun count(): Int
}
