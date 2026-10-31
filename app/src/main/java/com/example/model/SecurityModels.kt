package com.example.model

enum class Severity(val labelEn: String, val labelAr: String, val weight: Int) {
    CRITICAL("Critical", "حرجة", 25),
    HIGH("High", "مرتفعة", 15),
    MEDIUM("Medium", "متوسطة", 8),
    LOW("Low", "منخفضة", 3),
    INFO("Informational", "معلوماتية", 0)
}

enum class Confidence(val labelEn: String, val labelAr: String) {
    CONFIRMED("Confirmed", "مؤكدة"),
    PROBABLE("Probable", "محتملة"),
    NEEDS_MANUAL_VERIFICATION("Needs Manual Check", "تحتاج تحققاً يدوياً")
}

enum class Category(val labelEn: String, val labelAr: String) {
    TLS_SSL("TLS / SSL Configuration", "إعدادات تشفير TLS وSSL"),
    SECURITY_HEADERS("HTTP Security Headers", "الترويسات الأمنية HTTP"),
    COOKIES("Cookie Security", "أمان ملفات تعريف الارتباط"),
    INFO_DISCLOSURE("Information Disclosure", "كشف معلومات الخادم والتقنيات"),
    ARCHITECTURE("Architecture & Scope", "البنية ونطاق الاتصال")
}

data class SecurityFinding(
    val id: String,
    val title: String,
    val titleAr: String,
    val category: Category,
    val severity: Severity,
    val confidence: Confidence,
    val cvssScore: Double?,
    val cvssVector: String?,
    val owaspCategory: String,
    val cweId: String,
    val affectedComponent: String,
    val evidence: String,
    val explanationAr: String,
    val explanationEn: String,
    val impactAr: String,
    val impactEn: String,
    val remediationStepsAr: List<String>,
    val remediationStepsEn: List<String>,
    val configSnippet: String,
    val verificationCommand: String,
    val references: List<String>
)

data class AuditSummary(
    val id: String,
    val targetUrl: String,
    val scannedHost: String,
    val timestamp: Long,
    val durationMs: Long,
    val overallGrade: String,
    val score: Int,
    val isDemoScan: Boolean,
    val findings: List<SecurityFinding>,
    val executiveSummaryAr: String,
    val executiveSummaryEn: String,
    val technicalSummaryAr: String,
    val technicalSummaryEn: String,
    val tlsVersion: String,
    val tlsCipher: String,
    val certDaysRemaining: Int,
    val certIssuer: String,
    val scannedHeadersCount: Int,
    val testsRun: List<String>,
    val testsSkipped: List<String>
) {
    val criticalCount: Int get() = findings.count { it.severity == Severity.CRITICAL }
    val highCount: Int get() = findings.count { it.severity == Severity.HIGH }
    val mediumCount: Int get() = findings.count { it.severity == Severity.MEDIUM }
    val lowCount: Int get() = findings.count { it.severity == Severity.LOW }
    val infoCount: Int get() = findings.count { it.severity == Severity.INFO }
}

sealed class ScanState {
    object Idle : ScanState()
    data class Scanning(val step: String, val stepAr: String, val progress: Float) : ScanState()
    data class Success(val summary: AuditSummary) : ScanState()
    data class Error(val messageAr: String, val messageEn: String, val isSsrfBlocked: Boolean = false) : ScanState()
}

enum class TargetScope(val labelEn: String, val labelAr: String) {
    STRICT_HOST("Strict Hostname Only", "النطاق المحدد فقط (صارم)"),
    SAME_DOMAIN_SUBDOMAINS("Host & Subdomains", "النطاق والنطاقات الفرعية")
}
