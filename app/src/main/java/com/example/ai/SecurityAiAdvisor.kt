package com.example.ai

import com.example.model.AuditSummary
import com.example.model.Category
import com.example.model.SecurityFinding
import com.example.model.Severity

data class PostFixCheckItem(
    val id: String,
    val titleAr: String,
    val titleEn: String,
    val testCommand: String,
    val isChecked: Boolean = false
)

data class ResponsibleDisclosureDraft(
    val recipientTitle: String,
    val subject: String,
    val bodyMarkdown: String
)

interface AiAdvisorProvider {
    suspend fun generatePostFixChecklist(findings: List<SecurityFinding>): List<PostFixCheckItem>
    suspend fun generateResponsibleDisclosure(summary: AuditSummary): ResponsibleDisclosureDraft
    suspend fun generateTailoredFixSnippet(finding: SecurityFinding, webServer: String): String
}

object SecurityAiAdvisor : AiAdvisorProvider {

    override suspend fun generatePostFixChecklist(findings: List<SecurityFinding>): List<PostFixCheckItem> {
        val list = mutableListOf<PostFixCheckItem>()

        for (finding in findings) {
            val checkTitleAr = "التحقق من إصلاح: ${finding.titleAr}"
            val checkTitleEn = "Verify fix: ${finding.title}"
            list.add(
                PostFixCheckItem(
                    id = "CHK-${finding.id}",
                    titleAr = checkTitleAr,
                    titleEn = checkTitleEn,
                    testCommand = finding.verificationCommand,
                    isChecked = false
                )
            )
        }

        // Add general baseline check
        list.add(
            PostFixCheckItem(
                id = "CHK-RESTART-RELOAD",
                titleAr = "إعادة تحميل إعدادات الخادم (Graceful Reload) والتأكد من عدم وجود أخطاء في الصياغة (Syntax)",
                titleEn = "Gracefully reload web server configuration and verify syntax validity",
                testCommand = "nginx -t && systemctl reload nginx",
                isChecked = false
            )
        )

        return list
    }

    override suspend fun generateResponsibleDisclosure(summary: AuditSummary): ResponsibleDisclosureDraft {
        val criticalOrHighFindings = summary.findings.filter { it.severity == Severity.CRITICAL || it.severity == Severity.HIGH }

        val subject = "[Security Advisory] Defensive Audit Findings for ${summary.scannedHost} (Responsible Disclosure)"

        val body = """
            # تقرير الإبلاغ المسؤول عن الثغرات الأمنية (Responsible Disclosure)
            
            **إلى فريق أمن المعلومات / المطورين في:** ${summary.scannedHost}
            **تاريخ الفحص:** ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US).format(java.util.Date(summary.timestamp))}
            **نطاق الفحص المصرح به:** ${summary.targetUrl}
            **الدرجة الأمنية المحسوبة:** ${summary.overallGrade} (${summary.score}/100)
            
            ---
            
            ### 1. ملخص تنفيذي
            تم إجراء فحص دفاعي غير تخريبي (Non-Destructive Defensive Audit) لإعدادات وخوادم النطاق، وذلك ضمن إطار ممارسات الإبلاغ المسؤول ومعايير OWASP ASVS. 
            أظهرت النتائج وجود (${summary.criticalCount}) ثغرات حرجة و (${summary.highCount}) ثغرات عالية الخطورة بحاجة إلى معالجة وقائية لتعزيز خطوط الدفاع الرقمية.
            
            ### 2. أهم الملاحظات ذات الأولوية العالية
            ${
                if (criticalOrHighFindings.isEmpty()) {
                    "لم يتم رصد ثغرات حرجة أو عالية الخطورة في الفحص الأخير."
                } else {
                    criticalOrHighFindings.joinToString("\n\n") { f ->
                        """
                        * **[${f.severity.labelEn} / ${f.severity.labelAr}] ${f.titleAr} (${f.owaspCategory})**
                          - **المكون المتأثر:** `${f.affectedComponent}`
                          - **الدليل المرصود:** `${f.evidence}`
                          - **الأثر المحتمل:** ${f.impactAr}
                          - **إجراء الإصلاح الموصى به:** ${f.remediationStepsAr.joinToString("; ")}
                          - **المرجع:** ${f.cweId} | ${f.references.firstOrNull() ?: ""}
                        """.trimIndent()
                    }
                }
            }
            
            ### 3. إعدادات الإصلاح المقترحة (Configuration Snippets)
            لإصلاح الترويسات الأمنية دفعة واحدة في خادم Nginx، يُرجى تطبيق التوجيهات التالية داخل كتلة `server`:
            ```nginx
            # تطبيق الحماية الشاملة للترويسات
            add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
            add_header X-Frame-Options "SAMEORIGIN" always;
            add_header X-Content-Type-Options "nosniff" always;
            add_header Referrer-Policy "strict-origin-when-cross-origin" always;
            add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
            ```
            
            ### 4. طريقة التحقق بعد الإصلاح
            يمكن التحقق من تطبيق الإعدادات بنجاح عن طريق تنفيذ الأمر التالي:
            ```bash
            curl -sI ${summary.targetUrl} | grep -iE 'strict-transport|x-frame|content-security|x-content-type'
            ```
            
            ---
            *تم إنشاء هذا التقرير تلقائياً بواسطة AI Web Security Auditor - للاستخدام الدفاعي المسؤول فقط.*
        """.trimIndent()

        return ResponsibleDisclosureDraft(
            recipientTitle = "فريق الأمن السيبراني / إدارة الموقع",
            subject = subject,
            bodyMarkdown = body
        )
    }

    override suspend fun generateTailoredFixSnippet(finding: SecurityFinding, webServer: String): String {
        return when (webServer.lowercase()) {
            "apache" -> {
                when (finding.id) {
                    "HSTS-MISSING" -> "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
                    "CSP-MISSING" -> "Header set Content-Security-Policy \"default-src 'self'; script-src 'self';\""
                    "X-FRAME-OPTIONS-MISSING" -> "Header always append X-Frame-Options SAMEORIGIN"
                    "X-CONTENT-TYPE-OPTIONS-MISSING" -> "Header set X-Content-Type-Options nosniff"
                    "SERVER-BANNER-DISCLOSURE" -> "ServerTokens Prod\nServerSignature Off"
                    else -> finding.configSnippet
                }
            }
            "cloudflare" -> {
                "# Cloudflare Transform Rules -> Modify Response Header\nHeader: ${finding.affectedComponent}\nSet static value per best practice."
            }
            "express", "node" -> {
                "// Install helmet: npm install helmet\nconst helmet = require('helmet');\napp.use(helmet());"
            }
            else -> finding.configSnippet
        }
    }
}
