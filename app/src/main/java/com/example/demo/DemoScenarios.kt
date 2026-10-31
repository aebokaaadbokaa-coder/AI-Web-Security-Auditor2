package com.example.demo

import com.example.model.AuditSummary
import com.example.model.Category
import com.example.model.Confidence
import com.example.model.SecurityFinding
import com.example.model.Severity
import java.util.UUID

object DemoScenarios {

    fun getEcommerceDemo(): AuditSummary {
        val findings = listOf(
            SecurityFinding(
                id = "DEMO-HSTS-MISSING",
                title = "Missing HTTP Strict Transport Security (HSTS)",
                titleAr = "غياب ترويسة HSTS لفرض الاتصال المشفر",
                category = Category.SECURITY_HEADERS,
                severity = Severity.HIGH,
                confidence = Confidence.CONFIRMED,
                cvssScore = 6.5,
                cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                owaspCategory = "A05:2021-Security Misconfiguration",
                cweId = "CWE-523",
                affectedComponent = "HTTP Headers",
                evidence = "Strict-Transport-Security header is not present [DEMO DATA]",
                explanationAr = "يسمح غياب HSTS بهجمات خفض التشفير (SSL Stripping) في شبكات المقاهي والواي فاي العامة.",
                explanationEn = "Missing HSTS enables SSL stripping MitM attacks on public networks.",
                impactAr = "خطر اعتراض جلسات المتسوقين وسرقة بيانات الدفع.",
                impactEn = "Exposure of shopper sessions to cleartext eavesdropping.",
                remediationStepsAr = listOf("أضف ترويسة Strict-Transport-Security بمدة 31536000 ثانية."),
                remediationStepsEn = listOf("Add HSTS with max-age=31536000."),
                configSnippet = "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                verificationCommand = "curl -sI https://demo-ecommerce-store.example.com | grep -i strict-transport",
                references = listOf("https://owasp.org/www-project-secure-headers/")
            ),
            SecurityFinding(
                id = "DEMO-CSP-MISSING",
                title = "Missing Content-Security-Policy (CSP)",
                titleAr = "غياب سياسة أمان المحتوى (CSP)",
                category = Category.SECURITY_HEADERS,
                severity = Severity.HIGH,
                confidence = Confidence.CONFIRMED,
                cvssScore = 7.1,
                cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
                owaspCategory = "A05:2021-Security Misconfiguration",
                cweId = "CWE-1021",
                affectedComponent = "HTTP Headers",
                evidence = "No Content-Security-Policy header returned [DEMO DATA]",
                explanationAr = "لا توجد قيود على مصادر السكربتات المسموح بتحميلها في المتصفح.",
                explanationEn = "No restrictions on script execution sources, enabling Magecart-style web skimming.",
                impactAr = "خطر اختراق واجهات الدفع وسرقة بطاقات الائتمان (Web Skimming).",
                impactEn = "Web skimming risk targeting checkout forms.",
                remediationStepsAr = listOf("حدد سياسة CSP تمنع السكربتات غير المصرح بها."),
                remediationStepsEn = listOf("Deploy a restrictive Content-Security-Policy."),
                configSnippet = "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' https://js.stripe.com;\" always;",
                verificationCommand = "curl -sI https://demo-ecommerce-store.example.com | grep -i content-security",
                references = listOf("https://content-security-policy.com/")
            ),
            SecurityFinding(
                id = "DEMO-COOKIE-HTTPONLY",
                title = "Session Cookie 'cart_session' Missing HttpOnly",
                titleAr = "ملف تعريف الارتباط 'cart_session' يفتقر إلى خاصية HttpOnly",
                category = Category.COOKIES,
                severity = Severity.MEDIUM,
                confidence = Confidence.CONFIRMED,
                cvssScore = 5.3,
                cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                owaspCategory = "A05:2021-Security Misconfiguration",
                cweId = "CWE-1004",
                affectedComponent = "Set-Cookie: cart_session",
                evidence = "Set-Cookie: cart_session=abc987; Path=/; Secure [DEMO DATA]",
                explanationAr = "يمكن لأي نص برمجي في الصفحة قراءة معرّف سلة التسوق والجلسة عبر document.cookie.",
                explanationEn = "JavaScript can inspect the cookie, allowing theft if an XSS exists.",
                impactAr = "انتحال شخصية المشتري والاستيلاء على السلة والطلبات.",
                impactEn = "Account/cart takeover via client-side script theft.",
                remediationStepsAr = listOf("فعّل خيار HttpOnly لملف تعريف الارتباط."),
                remediationStepsEn = listOf("Enable HttpOnly flag on session cookie."),
                configSnippet = "Set-Cookie: cart_session=value; Path=/; Secure; HttpOnly; SameSite=Lax",
                verificationCommand = "curl -sI https://demo-ecommerce-store.example.com | grep -i set-cookie",
                references = listOf("https://owasp.org/www-community/HttpOnly")
            ),
            SecurityFinding(
                id = "DEMO-SERVER-BANNER",
                title = "Server Software Version Disclosed",
                titleAr = "كشف إصدار خادم Nginx بالتفصيل (Server Banner)",
                category = Category.INFO_DISCLOSURE,
                severity = Severity.LOW,
                confidence = Confidence.CONFIRMED,
                cvssScore = 3.1,
                cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                owaspCategory = "A05:2021-Security Misconfiguration",
                cweId = "CWE-200",
                affectedComponent = "HTTP Header: Server",
                evidence = "Server: nginx/1.18.0 (Ubuntu) [DEMO DATA]",
                explanationAr = "يكشف الخادم عن نوعه وإصداره ونظام التشغيل، مما يسهل البحث عن ثغراته.",
                explanationEn = "Exposing the exact Nginx version assists attackers in CVE research.",
                impactAr = "تسهيل استهداف الثغرات المعروفة للإصدار القديم.",
                impactEn = "Reconnaissance aid for known vulnerabilities.",
                remediationStepsAr = listOf("أضف server_tokens off; لإخفاء الإصدار."),
                remediationStepsEn = listOf("Configure server_tokens off;"),
                configSnippet = "server_tokens off;",
                verificationCommand = "curl -sI https://demo-ecommerce-store.example.com | grep -i server",
                references = listOf("https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens")
            )
        )

        return AuditSummary(
            id = UUID.randomUUID().toString(),
            targetUrl = "https://demo-ecommerce-store.example.com",
            scannedHost = "demo-ecommerce-store.example.com",
            timestamp = System.currentTimeMillis(),
            durationMs = 450,
            overallGrade = "C",
            score = 59,
            isDemoScan = true,
            findings = findings,
            executiveSummaryAr = "تقرير تجريبي: موقع تجارة إلكترونية افتراضي يعاني من غياب ترويسات HSTS و CSP مما يعرضه لمخاطر حقن السكربتات وهجمات الوسيط.",
            executiveSummaryEn = "Demo Report: Simulated E-Commerce store lacking CSP and HSTS headers, creating risks of Magecart skimming.",
            technicalSummaryAr = "تم فحص 4 ترويسات أمنية وكشف غياب HSTS و CSP ووجود كوكيز بدون HttpOnly مع تسريب ترويسة Nginx 1.18.0.",
            technicalSummaryEn = "Simulated evaluation of HTTP headers, cookies, and server banners.",
            tlsVersion = "TLSv1.2",
            tlsCipher = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            certDaysRemaining = 42,
            certIssuer = "Let's Encrypt Authority X3",
            scannedHeadersCount = 14,
            testsRun = listOf("TLS Handshake", "Security Headers", "Cookie Flags", "Server Banners"),
            testsSkipped = emptyList()
        )
    }

    fun getHardenedBankingDemo(): AuditSummary {
        val findings = listOf(
            SecurityFinding(
                id = "DEMO-INFO-PERFECTION",
                title = "Exemplary Security Posture",
                titleAr = "حالة أمنية نموذجية مطابقة لأفضل الممارسات",
                category = Category.ARCHITECTURE,
                severity = Severity.INFO,
                confidence = Confidence.CONFIRMED,
                cvssScore = 0.0,
                cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                owaspCategory = "Defense-in-Depth",
                cweId = "CWE-0",
                affectedComponent = "All Gateway Controls",
                evidence = "All headers present: HSTS preload, CSP nonce, Permissions-Policy, X-Frame-Options DENY, SameSite=Strict cookies [DEMO DATA]",
                explanationAr = "تم تطبيق كافة معايير الحماية المشددة بنجاح مع تشفير TLSv1.3 وعزل تام لإطارات العمل.",
                explanationEn = "All major defensive headers and TLS 1.3 protections are fully deployed.",
                impactAr = "حماية فائقة لبيانات العملاء والمعاملات المالية ضد هجمات XSS و MitM و Clickjacking.",
                impactEn = "Maximum defensive resilience against client and transport attacks.",
                remediationStepsAr = listOf("الاستمرار في المراقبة الدورية والتأكد من تجديد الشهادات الرقمية."),
                remediationStepsEn = listOf("Maintain continuous automated monitoring."),
                configSnippet = "# Server is fully hardened per OWASP ASVS Level 3",
                verificationCommand = "curl -sI https://demo-secure-bank.example.com",
                references = listOf("https://owasp.org/www-project-application-security-verification-standard/")
            )
        )

        return AuditSummary(
            id = UUID.randomUUID().toString(),
            targetUrl = "https://demo-secure-bank.example.com",
            scannedHost = "demo-secure-bank.example.com",
            timestamp = System.currentTimeMillis(),
            durationMs = 320,
            overallGrade = "A+",
            score = 100,
            isDemoScan = true,
            findings = findings,
            executiveSummaryAr = "تقرير تجريبي: بوابة مصرفية افتراضية مؤمنة بأعلى المعايير (درجة A+)، وتطبق كافة ترويسات الحماية والـ TLS 1.3.",
            executiveSummaryEn = "Demo Report: Fully hardened banking gateway adhering to OWASP ASVS Level 3 with perfect A+ score.",
            technicalSummaryAr = "تم التحقق من تشفير TLS 1.3، وترويسة HSTS مع preload، وسياسة CSP صارمة وكوكيز محمية بـ Strict SameSite.",
            technicalSummaryEn = "Hardened configuration verification complete.",
            tlsVersion = "TLSv1.3",
            tlsCipher = "TLS_AES_256_GCM_SHA384",
            certDaysRemaining = 240,
            certIssuer = "DigiCert Global Root G2",
            scannedHeadersCount = 22,
            testsRun = listOf("TLS Handshake", "Security Headers", "Cookie Flags", "Server Banners", "Permissions Policy"),
            testsSkipped = emptyList()
        )
    }
}
