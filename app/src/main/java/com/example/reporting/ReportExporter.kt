package com.example.reporting

import android.content.Context
import android.content.Intent
import com.example.data.AuditRepository
import com.example.model.AuditSummary
import com.example.model.Severity
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object ReportExporter {

    fun generateHtmlReport(summary: AuditSummary): String {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US)
        val formattedDate = dateFormat.format(Date(summary.timestamp))

        val criticalCount = summary.criticalCount
        val highCount = summary.highCount
        val mediumCount = summary.mediumCount
        val lowCount = summary.lowCount
        val infoCount = summary.infoCount

        val gradeColor = when (summary.overallGrade) {
            "A+", "A" -> "#00E676"
            "B" -> "#76FF03"
            "C" -> "#FFD600"
            "D" -> "#FF9100"
            else -> "#FF1744"
        }

        val findingsHtml = summary.findings.joinToString("\n") { f ->
            val badgeColor = when (f.severity) {
                Severity.CRITICAL -> "#FF1744"
                Severity.HIGH -> "#FF5252"
                Severity.MEDIUM -> "#FFD600"
                Severity.LOW -> "#00E5FF"
                Severity.INFO -> "#90A4AE"
            }
            """
            <div class="finding-card">
                <div class="finding-header">
                    <span class="severity-badge" style="background-color: $badgeColor;">${f.severity.labelEn} / ${f.severity.labelAr}</span>
                    <span class="finding-title">${f.titleAr} (${f.title})</span>
                </div>
                <div class="meta-row">
                    <span><strong>OWASP:</strong> ${f.owaspCategory}</span> | 
                    <span><strong>CWE:</strong> ${f.cweId}</span> | 
                    <span><strong>CVSS 3.1:</strong> ${f.cvssScore ?: "N/A"} (${f.cvssVector ?: ""})</span> | 
                    <span><strong>الثقة:</strong> ${f.confidence.labelAr}</span>
                </div>
                <div class="field-box">
                    <strong>المكون المتأثر:</strong> <code>${f.affectedComponent}</code>
                </div>
                <div class="field-box evidence">
                    <strong>الدليل المرصود (Evidence):</strong><br>
                    <code>${f.evidence}</code>
                </div>
                <p><strong>الشرح الفني:</strong> ${f.explanationAr}</p>
                <p><strong>الأثر والمخاطر:</strong> ${f.impactAr}</p>
                <div class="remediation-box">
                    <strong>خطوات الإصلاح المقترحة:</strong>
                    <ul>
                        ${f.remediationStepsAr.joinToString("") { "<li>$it</li>" }}
                    </ul>
                    ${if (f.configSnippet.isNotBlank()) "<strong>مثال الإعداد الآمن:</strong><pre><code>${f.configSnippet}</code></pre>" else ""}
                    ${if (f.verificationCommand.isNotBlank()) "<strong>أمر التحقق السريع:</strong><pre><code>${f.verificationCommand}</code></pre>" else ""}
                </div>
            </div>
            """.trimIndent()
        }

        return """
        <!DOCTYPE html>
        <html lang="ar" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>تقرير فحص أمني - ${summary.scannedHost}</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                    background-color: #070D18;
                    color: #E2E8F0;
                    margin: 0;
                    padding: 24px;
                    line-height: 1.6;
                }
                .container {
                    max-width: 900px;
                    margin: 0 auto;
                    background: #0F1A2E;
                    border: 1px solid #1E293B;
                    border-radius: 12px;
                    padding: 32px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
                }
                .header {
                    border-bottom: 2px solid #1E293B;
                    padding-bottom: 20px;
                    margin-bottom: 24px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    flex-wrap: wrap;
                }
                .score-badge {
                    font-size: 38px;
                    font-weight: bold;
                    color: $gradeColor;
                    background: #182846;
                    border: 2px solid $gradeColor;
                    border-radius: 12px;
                    padding: 8px 24px;
                    text-align: center;
                }
                .demo-banner {
                    background: #E65100;
                    color: white;
                    padding: 10px;
                    border-radius: 6px;
                    text-align: center;
                    font-weight: bold;
                    margin-bottom: 20px;
                }
                .summary-stats {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
                    gap: 12px;
                    margin: 20px 0;
                }
                .stat-card {
                    background: #182846;
                    border-radius: 8px;
                    padding: 14px;
                    text-align: center;
                    border: 1px solid #233554;
                }
                .stat-num {
                    font-size: 24px;
                    font-weight: bold;
                }
                .finding-card {
                    background: #132238;
                    border-radius: 8px;
                    border-right: 5px solid #00E5FF;
                    padding: 20px;
                    margin-bottom: 20px;
                }
                .finding-header {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    margin-bottom: 10px;
                }
                .severity-badge {
                    font-size: 12px;
                    font-weight: bold;
                    color: black;
                    padding: 4px 10px;
                    border-radius: 4px;
                }
                .finding-title {
                    font-size: 18px;
                    font-weight: bold;
                }
                .meta-row {
                    font-size: 13px;
                    color: #94A3B8;
                    margin-bottom: 12px;
                }
                .field-box {
                    background: #0B1526;
                    border-radius: 6px;
                    padding: 10px 14px;
                    margin: 10px 0;
                }
                .field-box.evidence code {
                    color: #00E5FF;
                }
                pre {
                    background: #050B14;
                    padding: 12px;
                    border-radius: 6px;
                    overflow-x: auto;
                    color: #A7F3D0;
                    direction: ltr;
                    text-align: left;
                }
                code {
                    font-family: monospace;
                }
                .footer {
                    margin-top: 40px;
                    padding-top: 16px;
                    border-top: 1px solid #1E293B;
                    text-align: center;
                    font-size: 12px;
                    color: #64748B;
                }
                @media print {
                    body { background: white; color: black; }
                    .container { box-shadow: none; border: none; background: white; }
                    .finding-card { background: #f8f9fa; border: 1px solid #ddd; }
                }
            </style>
        </head>
        <body>
            <div class="container">
                ${if (summary.isDemoScan) "<div class='demo-banner'>⚠️ هذا التقرير يحتوي على بيانات تجريبية (DEMO DATA) ⚠️</div>" else ""}
                
                <div class="header">
                    <div>
                        <h1 style="margin: 0; color: #00E5FF;">AI Web Security Auditor</h1>
                        <p style="margin: 4px 0 0 0; color: #94A3B8;">تقرير الفحص الأمني الدفاعي للموقع</p>
                        <p style="margin: 4px 0 0 0;"><strong>الهدف:</strong> <code>${summary.targetUrl}</code></p>
                        <p style="margin: 4px 0 0 0; font-size: 13px; color: #94A3B8;">التاريخ: $formattedDate | المدة: ${summary.durationMs}ms</p>
                    </div>
                    <div class="score-badge">
                        ${summary.overallGrade}
                        <div style="font-size: 14px; color: #E2E8F0;">${summary.score} / 100</div>
                    </div>
                </div>

                <div class="summary-stats">
                    <div class="stat-card">
                        <div class="stat-num" style="color: #FF1744;">$criticalCount</div>
                        <div style="font-size: 12px;">حرجة</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-num" style="color: #FF5252;">$highCount</div>
                        <div style="font-size: 12px;">مرتفعة</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-num" style="color: #FFD600;">$mediumCount</div>
                        <div style="font-size: 12px;">متوسطة</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-num" style="color: #00E5FF;">$lowCount</div>
                        <div style="font-size: 12px;">منخفضة</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-num" style="color: #90A4AE;">$infoCount</div>
                        <div style="font-size: 12px;">معلوماتية</div>
                    </div>
                </div>

                <h3>الملخص التنفيذي بالذكاء الاصطناعي (Executive Summary)</h3>
                <div class="field-box" style="white-space: pre-line;">${summary.executiveSummaryAr}</div>

                <h3>معلومات الاتصال والتشفير (Host & Transport Security)</h3>
                <div class="field-box">
                    <p><strong>بروتوكول TLS:</strong> ${summary.tlsVersion} | <strong>مجموعة التشفير:</strong> ${summary.tlsCipher}</p>
                    <p><strong>سلطة الشهادة:</strong> ${summary.certIssuer} | <strong>الأيام المتبقية للصلاحية:</strong> ${if (summary.certDaysRemaining >= 0) "${summary.certDaysRemaining} يوماً" else "غير محدد"}</p>
                    <p><strong>الترويسات المفحوصة:</strong> ${summary.scannedHeadersCount} ترويسة</p>
                </div>

                <h3>الملاحظات والثغرات التفصيلية (${summary.findings.size})</h3>
                $findingsHtml

                <div class="footer">
                    تم إنشاء هذا التقرير بواسطة AI Web Security Auditor وفق معايير OWASP ASVS و WSTG و CVSS v3.1.<br>
                    مخصص حصرياً للمطورين والمالكين المصرح لهم بغرض المعالجة الوقائية.
                </div>
            </div>
        </body>
        </html>
        """.trimIndent()
    }

    fun shareReport(context: Context, summary: AuditSummary) {
        val html = generateHtmlReport(summary)
        val file = File(context.cacheDir, "WebSec_Audit_${summary.scannedHost.replace(".", "_")}.html")
        FileOutputStream(file).use { it.write(html.toByteArray(Charsets.UTF_8)) }

        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/html"
            putExtra(Intent.EXTRA_SUBJECT, "Security Audit Report: ${summary.scannedHost}")
            putExtra(Intent.EXTRA_TEXT, summary.executiveSummaryAr)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(Intent.createChooser(shareIntent, "مشاركة تقرير الفحص الأمني"))
    }
}
