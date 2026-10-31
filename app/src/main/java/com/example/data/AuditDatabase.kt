package com.example.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.example.model.AuditSummary
import com.example.model.Category
import com.example.model.Confidence
import com.example.model.SecurityFinding
import com.example.model.Severity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject

@Database(entities = [AuditRecordEntity::class], version = 1, exportSchema = false)
abstract class AuditDatabase : RoomDatabase() {
    abstract fun auditDao(): AuditDao

    companion object {
        @Volatile
        private var INSTANCE: AuditDatabase? = null

        fun getDatabase(context: Context): AuditDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AuditDatabase::class.java,
                    "web_security_auditor.db"
                ).fallbackToDestructiveMigration().build()
                INSTANCE = instance
                instance
            }
        }
    }
}

class AuditRepository(private val dao: AuditDao) {

    fun getAuditHistory(): Flow<List<AuditRecordEntity>> {
        return dao.getAllRecords()
    }

    suspend fun saveAudit(summary: AuditSummary) {
        val json = serializeSummaryToJson(summary)
        val entity = AuditRecordEntity(
            id = summary.id,
            targetUrl = summary.targetUrl,
            scannedHost = summary.scannedHost,
            timestamp = summary.timestamp,
            overallGrade = summary.overallGrade,
            score = summary.score,
            isDemoScan = summary.isDemoScan,
            criticalCount = summary.criticalCount,
            highCount = summary.highCount,
            mediumCount = summary.mediumCount,
            lowCount = summary.lowCount,
            tlsVersion = summary.tlsVersion,
            summaryJson = json
        )
        dao.insertRecord(entity)
    }

    suspend fun getAuditById(id: String): AuditSummary? {
        val entity = dao.getRecordById(id) ?: return null
        return deserializeSummaryFromJson(entity.summaryJson)
    }

    suspend fun deleteAudit(id: String) {
        dao.deleteRecord(id)
    }

    suspend fun clearHistory() {
        dao.clearAll()
    }

    companion object {
        fun serializeSummaryToJson(summary: AuditSummary): String {
            val root = JSONObject()
            root.put("id", summary.id)
            root.put("targetUrl", summary.targetUrl)
            root.put("scannedHost", summary.scannedHost)
            root.put("timestamp", summary.timestamp)
            root.put("durationMs", summary.durationMs)
            root.put("overallGrade", summary.overallGrade)
            root.put("score", summary.score)
            root.put("isDemoScan", summary.isDemoScan)
            root.put("executiveSummaryAr", summary.executiveSummaryAr)
            root.put("executiveSummaryEn", summary.executiveSummaryEn)
            root.put("technicalSummaryAr", summary.technicalSummaryAr)
            root.put("technicalSummaryEn", summary.technicalSummaryEn)
            root.put("tlsVersion", summary.tlsVersion)
            root.put("tlsCipher", summary.tlsCipher)
            root.put("certDaysRemaining", summary.certDaysRemaining)
            root.put("certIssuer", summary.certIssuer)
            root.put("scannedHeadersCount", summary.scannedHeadersCount)

            val testsRunArr = JSONArray()
            summary.testsRun.forEach { testsRunArr.put(it) }
            root.put("testsRun", testsRunArr)

            val testsSkippedArr = JSONArray()
            summary.testsSkipped.forEach { testsSkippedArr.put(it) }
            root.put("testsSkipped", testsSkippedArr)

            val findingsArr = JSONArray()
            for (f in summary.findings) {
                val fObj = JSONObject()
                fObj.put("id", f.id)
                fObj.put("title", f.title)
                fObj.put("titleAr", f.titleAr)
                fObj.put("category", f.category.name)
                fObj.put("severity", f.severity.name)
                fObj.put("confidence", f.confidence.name)
                fObj.put("cvssScore", f.cvssScore ?: JSONObject.NULL)
                fObj.put("cvssVector", f.cvssVector ?: "")
                fObj.put("owaspCategory", f.owaspCategory)
                fObj.put("cweId", f.cweId)
                fObj.put("affectedComponent", f.affectedComponent)
                fObj.put("evidence", f.evidence)
                fObj.put("explanationAr", f.explanationAr)
                fObj.put("explanationEn", f.explanationEn)
                fObj.put("impactAr", f.impactAr)
                fObj.put("impactEn", f.impactEn)
                fObj.put("configSnippet", f.configSnippet)
                fObj.put("verificationCommand", f.verificationCommand)

                val remArArr = JSONArray()
                f.remediationStepsAr.forEach { remArArr.put(it) }
                fObj.put("remediationStepsAr", remArArr)

                val remEnArr = JSONArray()
                f.remediationStepsEn.forEach { remEnArr.put(it) }
                fObj.put("remediationStepsEn", remEnArr)

                val refArr = JSONArray()
                f.references.forEach { refArr.put(it) }
                fObj.put("references", refArr)

                findingsArr.put(fObj)
            }
            root.put("findings", findingsArr)

            return root.toString()
        }

        fun deserializeSummaryFromJson(jsonStr: String): AuditSummary? {
            return try {
                val root = JSONObject(jsonStr)
                val findings = mutableListOf<SecurityFinding>()
                val fArr = root.optJSONArray("findings")
                if (fArr != null) {
                    for (i in 0 until fArr.length()) {
                        val fObj = fArr.getJSONObject(i)
                        val remArList = mutableListOf<String>()
                        val remArArr = fObj.optJSONArray("remediationStepsAr")
                        if (remArArr != null) {
                            for (j in 0 until remArArr.length()) remArList.add(remArArr.getString(j))
                        }

                        val remEnList = mutableListOf<String>()
                        val remEnArr = fObj.optJSONArray("remediationStepsEn")
                        if (remEnArr != null) {
                            for (j in 0 until remEnArr.length()) remEnList.add(remEnArr.getString(j))
                        }

                        val refList = mutableListOf<String>()
                        val refArr = fObj.optJSONArray("references")
                        if (refArr != null) {
                            for (j in 0 until refArr.length()) refList.add(refArr.getString(j))
                        }

                        findings.add(
                            SecurityFinding(
                                id = fObj.optString("id"),
                                title = fObj.optString("title"),
                                titleAr = fObj.optString("titleAr"),
                                category = Category.valueOf(fObj.optString("category", Category.SECURITY_HEADERS.name)),
                                severity = Severity.valueOf(fObj.optString("severity", Severity.MEDIUM.name)),
                                confidence = Confidence.valueOf(fObj.optString("confidence", Confidence.CONFIRMED.name)),
                                cvssScore = if (fObj.has("cvssScore") && !fObj.isNull("cvssScore")) fObj.optDouble("cvssScore") else null,
                                cvssVector = fObj.optString("cvssVector"),
                                owaspCategory = fObj.optString("owaspCategory"),
                                cweId = fObj.optString("cweId"),
                                affectedComponent = fObj.optString("affectedComponent"),
                                evidence = fObj.optString("evidence"),
                                explanationAr = fObj.optString("explanationAr"),
                                explanationEn = fObj.optString("explanationEn"),
                                impactAr = fObj.optString("impactAr"),
                                impactEn = fObj.optString("impactEn"),
                                remediationStepsAr = remArList,
                                remediationStepsEn = remEnList,
                                configSnippet = fObj.optString("configSnippet"),
                                verificationCommand = fObj.optString("verificationCommand"),
                                references = refList
                            )
                        )
                    }
                }

                val testsRunList = mutableListOf<String>()
                val trArr = root.optJSONArray("testsRun")
                if (trArr != null) {
                    for (i in 0 until trArr.length()) testsRunList.add(trArr.getString(i))
                }

                val testsSkippedList = mutableListOf<String>()
                val tsArr = root.optJSONArray("testsSkipped")
                if (tsArr != null) {
                    for (i in 0 until tsArr.length()) testsSkippedList.add(tsArr.getString(i))
                }

                AuditSummary(
                    id = root.optString("id"),
                    targetUrl = root.optString("targetUrl"),
                    scannedHost = root.optString("scannedHost"),
                    timestamp = root.optLong("timestamp"),
                    durationMs = root.optLong("durationMs"),
                    overallGrade = root.optString("overallGrade", "B"),
                    score = root.optInt("score", 70),
                    isDemoScan = root.optBoolean("isDemoScan", false),
                    findings = findings,
                    executiveSummaryAr = root.optString("executiveSummaryAr"),
                    executiveSummaryEn = root.optString("executiveSummaryEn"),
                    technicalSummaryAr = root.optString("technicalSummaryAr"),
                    technicalSummaryEn = root.optString("technicalSummaryEn"),
                    tlsVersion = root.optString("tlsVersion"),
                    tlsCipher = root.optString("tlsCipher"),
                    certDaysRemaining = root.optInt("certDaysRemaining", -1),
                    certIssuer = root.optString("certIssuer"),
                    scannedHeadersCount = root.optInt("scannedHeadersCount", 0),
                    testsRun = testsRunList,
                    testsSkipped = testsSkippedList
                )
            } catch (e: Exception) {
                null
            }
        }
    }
}
