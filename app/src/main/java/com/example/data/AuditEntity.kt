package com.example.data

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "audit_records")
data class AuditRecordEntity(
    @PrimaryKey val id: String,
    val targetUrl: String,
    val scannedHost: String,
    val timestamp: Long,
    val overallGrade: String,
    val score: Int,
    val isDemoScan: Boolean,
    val criticalCount: Int,
    val highCount: Int,
    val mediumCount: Int,
    val lowCount: Int,
    val tlsVersion: String,
    val summaryJson: String
)

@Dao
interface AuditDao {
    @Query("SELECT * FROM audit_records ORDER BY timestamp DESC")
    fun getAllRecords(): Flow<List<AuditRecordEntity>>

    @Query("SELECT * FROM audit_records WHERE id = :recordId LIMIT 1")
    suspend fun getRecordById(recordId: String): AuditRecordEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertRecord(record: AuditRecordEntity)

    @Query("DELETE FROM audit_records WHERE id = :recordId")
    suspend fun deleteRecord(recordId: String)

    @Query("DELETE FROM audit_records")
    suspend fun clearAll()
}
