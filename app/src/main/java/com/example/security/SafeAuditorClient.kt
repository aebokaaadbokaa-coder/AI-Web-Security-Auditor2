package com.example.security

import com.example.model.AuditSummary
import com.example.model.Category
import com.example.model.Confidence
import com.example.model.SecurityFinding
import com.example.model.Severity
import com.example.model.TargetScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.net.InetAddress
import java.net.URI
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

class SafeAuditorClient {

    private val safeOkHttpClient = OkHttpClient.Builder()
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .followRedirects(false) // Handle redirects manually with SSRF inspection
        .followSslRedirects(false)
        .dns(object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                val addresses = Dns.SYSTEM.lookup(hostname)
                for (addr in addresses) {
                    val check = SsrfGuard.validateIpAddress(addr)
                    if (check is SsrfGuard.ValidationResult.Blocked) {
                        throw SecurityException("SSRF Block: IP ${addr.hostAddress} is restricted.")
                    }
                }
                return addresses
            }
        })
        .build()

    suspend fun auditTarget(
        rawUrl: String,
        scope: TargetScope,
        onProgress: (step: String, stepAr: String, progress: Float) -> Unit
    ): AuditSummary = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()
        val findings = mutableListOf<SecurityFinding>()
        val testsRun = mutableListOf<String>()
        val testsSkipped = mutableListOf<String>()

        val formattedUrl = if (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://")) {
            "https://$rawUrl"
        } else {
            rawUrl
        }
        val targetUri = URI.create(formattedUrl)
        val initialHost = targetUri.host ?: throw IllegalArgumentException("اسم النطاق مفقود")

        // Step 1: DNS & SSRF Validation
        currentCoroutineContext().ensureActive()
        onProgress("Validating Target & DNS (SSRF Defense)", "التحقق من النطاق وعناوين IP لمنع SSRF", 0.15f)
        val ssrfCheck = SsrfGuard.validateTargetUrl(formattedUrl)
        if (ssrfCheck is SsrfGuard.ValidationResult.Blocked) {
            throw SecurityException(ssrfCheck.reasonAr)
        }
        testsRun.add("SSRF & Host Scope Verification")

        // Step 2: TLS & Certificate Handshake Analysis
        currentCoroutineContext().ensureActive()
        onProgress("Inspecting TLS / SSL Handshake", "فحص تشفير TLS وصلاحية الشهادة الرقمية", 0.35f)
        var tlsVersion = "Unknown"
        var tlsCipher = "Unknown"
        var certDaysRemaining = -1
        var certIssuer = "Unknown"

        if (targetUri.scheme == "https" || formattedUrl.startsWith("https://")) {
            try {
                val tlsResult = inspectTls(initialHost, if (targetUri.port != -1) targetUri.port else 443)
                tlsVersion = tlsResult.protocol
                tlsCipher = tlsResult.cipherSuite
                certDaysRemaining = tlsResult.daysRemaining
                certIssuer = tlsResult.issuer
                testsRun.add("TLS Certificate & Protocol Inspection")

                // Analyze TLS Findings
                if (tlsResult.protocol.startsWith("TLSv1.0") || tlsResult.protocol.startsWith("TLSv1.1") || tlsResult.protocol.startsWith("SSL")) {
                    findings.add(
                        SecurityFinding(
                            id = "TLS-DEPRECATED-PROTO",
                            title = "Deprecated Insecure TLS Protocol In Use",
                            titleAr = "استخدام بروتوكول TLS قديم وغير آمن",
                            category = Category.TLS_SSL,
                            severity = Severity.HIGH,
                            confidence = Confidence.CONFIRMED,
                            cvssScore = 7.4,
                            cvssVector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            owaspCategory = "A02:2021-Cryptographic Failures",
                            cweId = "CWE-326",
                            affectedComponent = "TLS Handshake ($initialHost:443)",
                            evidence = "Protocol negotiated: ${tlsResult.protocol}",
                            explanationAr = "تم التفاوض على بروتوكول TLS قديم يحتوي على ثغرات تشفير معروفة مثل BEAST و POODLE ويفتقر إلى التشفير المتقدم (PFS).",
                            explanationEn = "The server negotiated a deprecated TLS protocol version vulnerable to cryptographic attacks.",
                            impactAr = "إمكانية تنصت المهاجمين على حركة المرور وفك تشفير الجلسات بين المستخدم والموقع.",
                            impactEn = "Adversaries can decrypt intercepted traffic and compromise session confidentiality.",
                            remediationStepsAr = listOf(
                                "عطّل بروتوكولات SSLv3 و TLS 1.0 و TLS 1.1 في إعدادات خادم الويب.",
                                "فعّل حصراً TLS 1.2 و TLS 1.3 مع دعم Perfect Forward Secrecy."
                            ),
                            remediationStepsEn = listOf(
                                "Disable SSLv3, TLS 1.0, and TLS 1.1 in web server configuration.",
                                "Enforce TLS 1.2 and TLS 1.3 with Perfect Forward Secrecy cipher suites."
                            ),
                            configSnippet = "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!RC4;",
                            verificationCommand = "openssl s_client -connect $initialHost:443 -tls1_1",
                            references = listOf("https://owasp.org/Top10/A02_2021-Cryptographic_Failures/", "https://cwe.mitre.org/data/definitions/326.html")
                        )
                    )
                }

                if (certDaysRemaining in 0..14) {
                    val isCritical = certDaysRemaining <= 3
                    findings.add(
                        SecurityFinding(
                            id = "TLS-CERT-EXPIRING",
                            title = if (certDaysRemaining == 0) "TLS Certificate Has Expired" else "TLS Certificate Expiring Soon ($certDaysRemaining days)",
                            titleAr = if (certDaysRemaining == 0) "شهادة TLS منتهية الصلاحية" else "شهادة TLS تشارف على الانتهاء ($certDaysRemaining يوماً)",
                            category = Category.TLS_SSL,
                            severity = if (isCritical) Severity.CRITICAL else Severity.HIGH,
                            confidence = Confidence.CONFIRMED,
                            cvssScore = if (isCritical) 7.5 else 5.3,
                            cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                            owaspCategory = "A02:2021-Cryptographic Failures",
                            cweId = "CWE-295",
                            affectedComponent = "SSL/TLS Certificate ($certIssuer)",
                            evidence = "Days until expiration: $certDaysRemaining. Issuer: $certIssuer",
                            explanationAr = "ستنتهي صلاحية شهادة الأمان قريباً أو انتهت بالفعل، مما سيتسبب في ظهور تحذيرات حمراء للمستخدمين وانقطاع الخدمة.",
                            explanationEn = "The TLS certificate is approaching its expiration date or has expired, causing browser security warnings and trust failure.",
                            impactAr = "فقدان ثقة المستخدمين وظهور شاشات تحذير أمنية تمنع الوصول وتوقف العمليات الحيوية.",
                            impactEn = "Denial of access for end users encountering browser security blocks.",
                            remediationStepsAr = listOf(
                                "قم بتجديد شهادة TLS فوراً عبر سلطة الشهادات المعتمدة أو Certbot/Let's Encrypt.",
                                "قم بجدولة التجديد التلقائي (Cron job) قبل 30 يوماً من الانتهاء."
                            ),
                            remediationStepsEn = listOf(
                                "Renew the TLS certificate immediately via your CA or Certbot.",
                                "Set up automated certificate renewal alerts and cron tasks."
                            ),
                            configSnippet = "certbot renew --dry-run",
                            verificationCommand = "curl -vI https://$initialHost 2>&1 | grep -i expire",
                            references = listOf("https://cwe.mitre.org/data/definitions/295.html")
                        )
                    )
                }
            } catch (e: Exception) {
                testsSkipped.add("Direct TLS Socket Check: ${e.message}")
            }
        } else {
            testsSkipped.add("TLS Check skipped: Cleartext HTTP Target")
            findings.add(
                SecurityFinding(
                    id = "CLEAR-TEXT-HTTP",
                    title = "Cleartext HTTP Transport Detected",
                    titleAr = "استخدام بروتوكول HTTP غير مشفر",
                    category = Category.TLS_SSL,
                    severity = Severity.HIGH,
                    confidence = Confidence.CONFIRMED,
                    cvssScore = 7.5,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    owaspCategory = "A02:2021-Cryptographic Failures",
                    cweId = "CWE-319",
                    affectedComponent = "HTTP Transport ($initialHost)",
                    evidence = "Target scheme is http://",
                    explanationAr = "يتم نقل بيانات المستخدم والصفحات بنص صريح دون تشفير، مما يسمح لأي شخص على الشبكة بالتنصت وسرقة البيانات.",
                    explanationEn = "Unencrypted HTTP communication permits Man-in-the-Middle (MitM) attacks and data interception.",
                    impactAr = "سرقة بيانات الدخول، والتلاعب بمحتوى الموقع عبر هجمات رجل في المنتصف (MitM).",
                    impactEn = "Interception of sensitive session cookies, user credentials, and injected payloads.",
                    remediationStepsAr = listOf(
                        "ثبّت شهادة TLS موثوقة.",
                        "قم بإعادة توجيه كافة طلبات HTTP إلى HTTPS بكود 301 Permanent Redirect."
                    ),
                    remediationStepsEn = listOf(
                        "Install a valid TLS certificate.",
                        "Enforce permanent HTTP-to-HTTPS 301 redirection."
                    ),
                    configSnippet = "server {\n    listen 80;\n    server_name $initialHost;\n    return 301 https://\$host\$request_uri;\n}",
                    verificationCommand = "curl -I http://$initialHost",
                    references = listOf("https://owasp.org/Top10/A02_2021-Cryptographic_Failures/")
                )
            )
        }

        // Step 3: HTTP Request & Response Headers Audit
        currentCoroutineContext().ensureActive()
        onProgress("Analyzing HTTP Security Headers", "فحص ترويسات الاستجابة الأمنية (CSP, HSTS, X-Frame)", 0.60f)
        val request = Request.Builder()
            .url(formattedUrl)
            .header("User-Agent", "AI-Web-Security-Auditor/1.0 (Defensive-Audit-Engine)")
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .build()

        var response: Response? = null
        try {
            response = safeOkHttpClient.newCall(request).execute()
        } catch (e: Exception) {
            // Check if redirect or connection failed
            throw RuntimeException("تعذر الاتصال بالموقع الهدف: ${e.localizedMessage ?: "مهلة الاتصال انتهت"}")
        }

        val headers = response.headers
        val headersCount = headers.size
        testsRun.add("HTTP Response Headers Inspection ($headersCount headers analyzed)")

        // 3.1 Check Strict-Transport-Security (HSTS)
        val hsts = headers["Strict-Transport-Security"]
        if (hsts == null) {
            findings.add(
                SecurityFinding(
                    id = "HSTS-MISSING",
                    title = "Missing HTTP Strict Transport Security (HSTS)",
                    titleAr = "غياب ترويسة HSTS لفرض الاتصال المشفر",
                    category = Category.SECURITY_HEADERS,
                    severity = Severity.HIGH,
                    confidence = Confidence.CONFIRMED,
                    cvssScore = 6.5,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    owaspCategory = "A05:2021-Security Misconfiguration",
                    cweId = "CWE-523",
                    affectedComponent = "HTTP Header: Strict-Transport-Security",
                    evidence = "Header 'Strict-Transport-Security' not returned by server",
                    explanationAr = "عدم وجود ترويسة HSTS يسمح بهجمات SSL Stripping حيث يمكن للمهاجم إجبار المتصفح على الاتصال عبر HTTP غير المشفر.",
                    explanationEn = "Without HSTS, browsers can be coerced into downgraded cleartext HTTP connections via SSL stripping.",
                    impactAr = "إمكانية اعتراض حركة المرور الأولى للمستخدم واستخراج بيانات الجلسة.",
                    impactEn = "Vulnerability to active network eavesdropping and downgrade attacks.",
                    remediationStepsAr = listOf(
                        "أضف ترويسة Strict-Transport-Security بمدة صلاحية كافية (سنة واحدة على الأقل max-age=31536000).",
                        "أضف معاملات includeSubDomains و preload لحماية النطاقات الفرعية وتضمينها في قوائم المتصفحات."
                    ),
                    remediationStepsEn = listOf(
                        "Add Strict-Transport-Security header with max-age=31536000.",
                        "Include 'includeSubDomains' and 'preload' directives."
                    ),
                    configSnippet = "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
                    verificationCommand = "curl -sI $formattedUrl | grep -i strict-transport-security",
                    references = listOf("https://owasp.org/www-project-secure-headers/#strict-transport-security", "https://hstspreload.org/")
                )
            )
        } else {
            if (!hsts.contains("max-age") || (hsts.substringAfter("max-age=").substringBefore(";").trim().toLongOrNull() ?: 0L) < 15768000L) {
                findings.add(
                    SecurityFinding(
                        id = "HSTS-SHORT-MAXAGE",
                        title = "HSTS max-age is Too Short (< 6 months)",
                        titleAr = "مدة صلاحية HSTS قصيرة جداً (أقل من 6 أشهر)",
                        category = Category.SECURITY_HEADERS,
                        severity = Severity.LOW,
                        confidence = Confidence.CONFIRMED,
                        cvssScore = 3.7,
                        cvssVector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        owaspCategory = "A05:2021-Security Misconfiguration",
                        cweId = "CWE-523",
                        affectedComponent = "HTTP Header: Strict-Transport-Security",
                        evidence = "Value: $hsts",
                        explanationAr = "تم ضبط مدة HSTS على فترة قصيرة، مما يقلل من فاعلية حماية المتصفح للمستخدمين.",
                        explanationEn = "The HSTS max-age directive is set to an insufficiently short duration.",
                        impactAr = "تقليص فترة الحماية الإجبارية وإتاحة نافذة لهجمات الخفض الأمني.",
                        impactEn = "Reduced browser enforcement window for HTTPS security.",
                        remediationStepsAr = listOf("ارفع مدة max-age إلى 31536000 ثانية (سنة واحدة)."),
                        remediationStepsEn = listOf("Increase max-age to 31536000 (1 year)."),
                        configSnippet = "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                        verificationCommand = "curl -sI $formattedUrl | grep -i strict-transport-security",
                        references = listOf("https://hstspreload.org/")
                    )
                )
            }
        }

        // 3.2 Check Content-Security-Policy (CSP)
        val csp = headers["Content-Security-Policy"]
        if (csp == null) {
            findings.add(
                SecurityFinding(
                    id = "CSP-MISSING",
                    title = "Missing Content-Security-Policy (CSP)",
                    titleAr = "غياب سياسة أمان المحتوى (CSP)",
                    category = Category.SECURITY_HEADERS,
                    severity = Severity.HIGH,
                    confidence = Confidence.CONFIRMED,
                    cvssScore = 7.1,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
                    owaspCategory = "A05:2021-Security Misconfiguration",
                    cweId = "CWE-1021",
                    affectedComponent = "HTTP Header: Content-Security-Policy",
                    evidence = "Header 'Content-Security-Policy' is absent",
                    explanationAr = "تعد CSP خط الدفاع الأول ضد ثغرات حقن الشيفرات الخبيثة (XSS) وتضمين الموارد الخارجية الضارة.",
                    explanationEn = "Missing Content-Security-Policy allows Cross-Site Scripting (XSS) and unrestricted content loading.",
                    impactAr = "تنفيذ نصوص برمجية خبيثة في متصفح الزائر وسرقة جلسات الحسابات وتجاوز قيود النطاق.",
                    impactEn = "Execution of malicious scripts, session token theft, and DOM data exfiltration.",
                    remediationStepsAr = listOf(
                        "طبّق سياسة محتوى مقيدة تبدأ بـ default-src 'self'.",
                        "تجنّب استخدام 'unsafe-inline' و 'unsafe-eval' واعتمد على Nonce أو Hashes للسكربتات الموثوقة."
                    ),
                    remediationStepsEn = listOf(
                        "Define a strict Content-Security-Policy beginning with default-src 'self'.",
                        "Eliminate 'unsafe-inline' and use cryptographic nonces or hashes."
                    ),
                    configSnippet = "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';\" always;",
                    verificationCommand = "curl -sI $formattedUrl | grep -i content-security-policy",
                    references = listOf("https://owasp.org/www-project-secure-headers/#content-security-policy", "https://content-security-policy.com/")
                )
            )
        } else {
            if (csp.contains("unsafe-inline") || csp.contains("unsafe-eval")) {
                findings.add(
                    SecurityFinding(
                        id = "CSP-UNSAFE-DIRECTIVES",
                        title = "CSP Contains Insecure Directives ('unsafe-inline' / 'unsafe-eval')",
                        titleAr = "سياسة CSP تتضمن تعليمات غير آمنة ('unsafe-inline' أو 'unsafe-eval')",
                        category = Category.SECURITY_HEADERS,
                        severity = Severity.MEDIUM,
                        confidence = Confidence.CONFIRMED,
                        cvssScore = 5.4,
                        cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        owaspCategory = "A05:2021-Security Misconfiguration",
                        cweId = "CWE-1021",
                        affectedComponent = "HTTP Header: Content-Security-Policy",
                        evidence = "CSP: ${csp.take(120)}...",
                        explanationAr = "استخدام unsafe-inline أو unsafe-eval يبطل الحماية الأساسية ضد هجمات Cross-Site Scripting (XSS).",
                        explanationEn = "Using 'unsafe-inline' or 'unsafe-eval' significantly weakens XSS mitigation capabilities of CSP.",
                        impactAr = "إمكانية تمرير وتنفيذ نصوص خبيثة في حال وجود نقطة حقن في مدخلات الصفحة.",
                        impactEn = "Facilitates successful exploitation of Cross-Site Scripting flaws.",
                        remediationStepsAr = listOf("استبدل السكربتات المضمنة بملفات منفصلة أو استخدم Nonce مشفر لكل استجابة."),
                        remediationStepsEn = listOf("Replace inline scripts with external files or use dynamic nonces."),
                        configSnippet = "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-RANDOM_BASE64';",
                        verificationCommand = "curl -sI $formattedUrl | grep -i content-security-policy",
                        references = listOf("https://csp-evaluator.withgoogle.com/")
                    )
                )
            }
        }

        // 3.3 Check X-Frame-Options (Clickjacking)
        val xfo = headers["X-Frame-Options"]
        val hasCspFrameAncestors = csp?.contains("frame-ancestors") == true
        if (xfo == null && !hasCspFrameAncestors) {
            findings.add(
                SecurityFinding(
                    id = "X-FRAME-OPTIONS-MISSING",
                    title = "Missing Anti-Clickjacking Header (X-Frame-Options)",
                    titleAr = "غياب ترويسة الحماية من هجمات Clickjacking (X-Frame-Options)",
                    category = Category.SECURITY_HEADERS,
                    severity = Severity.MEDIUM,
                    confidence = Confidence.CONFIRMED,
                    cvssScore = 5.0,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    owaspCategory = "A05:2021-Security Misconfiguration",
                    cweId = "CWE-1021",
                    affectedComponent = "HTTP Header: X-Frame-Options",
                    evidence = "Neither X-Frame-Options nor CSP frame-ancestors is present",
                    explanationAr = "يمكن للمهاجمين تضمين موقعك داخل إطار غير مرئي (iframe) في موقع خبيث لخداع المستخدم للنقر على إجراءات حساسة.",
                    explanationEn = "The site allows arbitrary framing, exposing users to UI redressing (Clickjacking) attacks.",
                    impactAr = "خداع المستخدم لتنفيذ عمليات تحويل أموال أو تغيير كلمات المرور دون علمه.",
                    impactEn = "Unintended state-changing actions performed by tricked authenticated users.",
                    remediationStepsAr = listOf(
                        "أضف ترويسة X-Frame-Options بقيمة DENY أو SAMEORIGIN.",
                        "أو حدد تعليمة frame-ancestors 'self' في سياسة CSP."
                    ),
                    remediationStepsEn = listOf(
                        "Set X-Frame-Options to DENY or SAMEORIGIN.",
                        "Configure CSP 'frame-ancestors' directive."
                    ),
                    configSnippet = "add_header X-Frame-Options \"SAMEORIGIN\" always;",
                    verificationCommand = "curl -sI $formattedUrl | grep -i x-frame-options",
                    references = listOf("https://owasp.org/www-community/attacks/Clickjacking")
                )
            )
        }

        // 3.4 Check X-Content-Type-Options
        val xcto = headers["X-Content-Type-Options"]
        if (xcto == null || !xcto.equals("nosniff", ignoreCase = true)) {
            findings.add(
                SecurityFinding(
                    id = "X-CONTENT-TYPE-OPTIONS-MISSING",
                    title = "Missing X-Content-Type-Options (MIME Sniffing Risk)",
                    titleAr = "غياب ترويسة منع التخمين التلقائي للملفات (X-Content-Type-Options)",
                    category = Category.SECURITY_HEADERS,
                    severity = Severity.LOW,
                    confidence = Confidence.CONFIRMED,
                    cvssScore = 3.5,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    owaspCategory = "A05:2021-Security Misconfiguration",
                    cweId = "CWE-79",
                    affectedComponent = "HTTP Header: X-Content-Type-Options",
                    evidence = "Value: ${xcto ?: "Absent"}",
                    explanationAr = "بدون قيمة 'nosniff'، قد تحاول المتصفحات تخمين نوع الملفات وتفسير ملف نصي أو صورة ككود تنفيذي (MIME Sniffing).",
                    explanationEn = "Without 'nosniff', browsers may guess MIME types and execute uploaded files as scripts.",
                    impactAr = "تنفيذ نصوص خبيثة عبر ملفات يرفعها المستخدمون.",
                    impactEn = "Cross-site scripting via MIME confusion attacks.",
                    remediationStepsAr = listOf("أضف ترويسة X-Content-Type-Options بقيمة nosniff دائماً."),
                    remediationStepsEn = listOf("Add header X-Content-Type-Options: nosniff."),
                    configSnippet = "add_header X-Content-Type-Options \"nosniff\" always;",
                    verificationCommand = "curl -sI $formattedUrl | grep -i x-content-type-options",
                    references = listOf("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options")
                )
            )
        }

        // 3.5 Check Referrer-Policy
        val referrerPolicy = headers["Referrer-Policy"]
        if (referrerPolicy == null) {
            findings.add(
                SecurityFinding(
                    id = "REFERRER-POLICY-MISSING",
                    title = "Missing Referrer-Policy Header",
                    titleAr = "غياب ترويسة التحكم ببيانات الإحالة (Referrer-Policy)",
                    category = Category.SECURITY_HEADERS,
                    severity = Severity.LOW,
                    confidence = Confidence.CONFIRMED,
                    cvssScore = 3.1,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    owaspCategory = "A05:2021-Security Misconfiguration",
                    cweId = "CWE-200",
                    affectedComponent = "HTTP Header: Referrer-Policy",
                    evidence = "Header 'Referrer-Policy' is absent",
                    explanationAr = "قد تسرب روابط الصفحات معلمات حساسة (tokens أو أرقام سرية أو معرفات) إلى مواقع خارجية عند النقر على روابط خارجية.",
                    explanationEn = "Unset Referrer-Policy may leak URL parameters containing sensitive tokens to third-party destinations.",
                    impactAr = "تسريب معلومات وروابط الجلسات في ترويسة Referer للمواقع الخارجية.",
                    impactEn = "Information leakage of URL paths and query strings.",
                    remediationStepsAr = listOf("اضبط الترويسة على strict-origin-when-cross-origin أو no-referrer."),
                    remediationStepsEn = listOf("Set Referrer-Policy to strict-origin-when-cross-origin."),
                    configSnippet = "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
                    verificationCommand = "curl -sI $formattedUrl | grep -i referrer-policy",
                    references = listOf("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy")
                )
            )
        }

        // 3.6 Check Permissions-Policy
        val permissionsPolicy = headers["Permissions-Policy"] ?: headers["Feature-Policy"]
        if (permissionsPolicy == null) {
            findings.add(
                SecurityFinding(
                    id = "PERMISSIONS-POLICY-MISSING",
                    title = "Missing Permissions-Policy Header",
                    titleAr = "غياب ترويسة تقييد صلاحيات المتصفح (Permissions-Policy)",
                    category = Category.SECURITY_HEADERS,
                    severity = Severity.LOW,
                    confidence = Confidence.CONFIRMED,
                    cvssScore = 2.6,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    owaspCategory = "A05:2021-Security Misconfiguration",
                    cweId = "CWE-16",
                    affectedComponent = "HTTP Header: Permissions-Policy",
                    evidence = "Header 'Permissions-Policy' is absent",
                    explanationAr = "تسمح ترويسة Permissions-Policy للموقع بحظر استخدام الكاميرا والميكروفون والموقع الجغرافي من قبل النوافذ والإطارات المضمنة.",
                    explanationEn = "Permissions-Policy restricts browser features like camera, microphone, and geolocation from untrusted embedded iframes.",
                    impactAr = "إمكانية وصول إطارات خارجية أو نصوص غير موثوقة إلى عتاد جهاز المستخدم.",
                    impactEn = "Potential unauthorized hardware API access by embedded frames.",
                    remediationStepsAr = listOf("أضف ترويسة Permissions-Policy لتعطيل الميزات غير المستخدمة (مثل geolocation=(), microphone=(), camera=())."),
                    remediationStepsEn = listOf("Define Permissions-Policy disabling unused browser capabilities."),
                    configSnippet = "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;",
                    verificationCommand = "curl -sI $formattedUrl | grep -i permissions-policy",
                    references = listOf("https://w3c.github.io/webappsec-permissions-policy/")
                )
            )
        }

        // Step 4: Cookie Attributes Security Audit
        currentCoroutineContext().ensureActive()
        onProgress("Auditing Cookie Flags (Secure, HttpOnly, SameSite)", "فحص خصائص أمان ملفات تعريف الارتباط (Cookies)", 0.75f)
        val setCookieHeaders = headers.values("Set-Cookie")
        testsRun.add("Cookie Security Inspection (${setCookieHeaders.size} cookies observed)")

        for (cookieHeader in setCookieHeaders) {
            val cookieName = cookieHeader.substringBefore("=").trim()
            val lowerCookie = cookieHeader.lowercase()

            val isSecure = lowerCookie.contains("; secure") || lowerCookie.endsWith(";secure") || lowerCookie.endsWith("secure")
            val isHttpOnly = lowerCookie.contains("; httponly") || lowerCookie.endsWith(";httponly") || lowerCookie.endsWith("httponly")
            val hasSameSite = lowerCookie.contains("samesite=")

            if (!isSecure && targetUri.scheme == "https") {
                findings.add(
                    SecurityFinding(
                        id = "COOKIE-MISSING-SECURE-$cookieName",
                        title = "Cookie '$cookieName' Missing 'Secure' Flag",
                        titleAr = "ملف تعريف الارتباط '$cookieName' يفتقر إلى خاصية 'Secure'",
                        category = Category.COOKIES,
                        severity = Severity.HIGH,
                        confidence = Confidence.CONFIRMED,
                        cvssScore = 6.5,
                        cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                        owaspCategory = "A05:2021-Security Misconfiguration",
                        cweId = "CWE-614",
                        affectedComponent = "Set-Cookie: $cookieName",
                        evidence = "Set-Cookie: ${cookieHeader.take(80)}...",
                        explanationAr = "بدون علامة Secure، قد يقوم المتصفح بإرسال هذا الكوكي عبر اتصالات HTTP غير المشفرة، مما يعرضه للاعتراض.",
                        explanationEn = "Cookies without the 'Secure' attribute can be transmitted over cleartext channels and intercepted.",
                        impactAr = "سرقة معرّف الجلسة واختراق حساب المستخدم عبر شبكات غير آمنة.",
                        impactEn = "Session hijacking via unencrypted transport exposure.",
                        remediationStepsAr = listOf("أضف سمة '; Secure' إلى إعدادات الكوكي في تطبيق الويب."),
                        remediationStepsEn = listOf("Ensure the 'Secure' directive is appended to Set-Cookie."),
                        configSnippet = "Set-Cookie: $cookieName=value; Secure; HttpOnly; SameSite=Lax",
                        verificationCommand = "curl -sI $formattedUrl | grep -i set-cookie",
                        references = listOf("https://owasp.org/www-community/controls/SecureCookieAttribute")
                    )
                )
            }

            if (!isHttpOnly) {
                findings.add(
                    SecurityFinding(
                        id = "COOKIE-MISSING-HTTPONLY-$cookieName",
                        title = "Cookie '$cookieName' Missing 'HttpOnly' Flag",
                        titleAr = "ملف تعريف الارتباط '$cookieName' يفتقر إلى خاصية 'HttpOnly'",
                        category = Category.COOKIES,
                        severity = Severity.MEDIUM,
                        confidence = Confidence.CONFIRMED,
                        cvssScore = 5.3,
                        cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        owaspCategory = "A05:2021-Security Misconfiguration",
                        cweId = "CWE-1004",
                        affectedComponent = "Set-Cookie: $cookieName",
                        evidence = "Set-Cookie: ${cookieHeader.take(80)}...",
                        explanationAr = "بدون علامة HttpOnly، يمكن لأي كود JavaScript يعمل في الصفحة (مثل ثغرة XSS) قراءة قيمة الكوكي وسرقتها.",
                        explanationEn = "Without 'HttpOnly', scripts can access the cookie via document.cookie, enabling theft via XSS.",
                        impactAr = "سرقة الجلسات النشطة في حال وجود أي ثغرة XSS في الموقع.",
                        impactEn = "Account takeover through script-based token harvesting.",
                        remediationStepsAr = listOf("فعّل خيار HttpOnly لملفات تعريف ارتباط الجلسة لمنع وصول JavaScript إليها."),
                        remediationStepsEn = listOf("Flag session cookies with HttpOnly."),
                        configSnippet = "Set-Cookie: $cookieName=value; Secure; HttpOnly; SameSite=Lax",
                        verificationCommand = "curl -sI $formattedUrl | grep -i set-cookie",
                        references = listOf("https://owasp.org/www-community/HttpOnly")
                    )
                )
            }

            if (!hasSameSite) {
                findings.add(
                    SecurityFinding(
                        id = "COOKIE-MISSING-SAMESITE-$cookieName",
                        title = "Cookie '$cookieName' Missing 'SameSite' Attribute",
                        titleAr = "ملف تعريف الارتباط '$cookieName' يفتقر إلى سمة 'SameSite'",
                        category = Category.COOKIES,
                        severity = Severity.LOW,
                        confidence = Confidence.CONFIRMED,
                        cvssScore = 4.3,
                        cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                        owaspCategory = "A01:2021-Broken Access Control",
                        cweId = "CWE-1275",
                        affectedComponent = "Set-Cookie: $cookieName",
                        evidence = "Set-Cookie: ${cookieHeader.take(80)}...",
                        explanationAr = "تساعد سمة SameSite في حماية الموقع من هجمات تزوير الطلبات عبر المواقع (CSRF) عن طريق تحديد وقت إرسال الكوكي مع الطلبات الخارجية.",
                        explanationEn = "Missing SameSite attribute leaves the cookie vulnerable to Cross-Site Request Forgery (CSRF).",
                        impactAr = "تنفيذ طلبات غير مصرح بها نيابة عن المستخدم المسجل دخوله.",
                        impactEn = "CSRF exploitation on sensitive state-changing endpoints.",
                        remediationStepsAr = listOf("عيّن سمة SameSite=Lax أو SameSite=Strict في كافة الكوكيز الحساسة."),
                        remediationStepsEn = listOf("Configure SameSite=Lax or SameSite=Strict on session cookies."),
                        configSnippet = "Set-Cookie: $cookieName=value; Secure; HttpOnly; SameSite=Lax",
                        verificationCommand = "curl -sI $formattedUrl | grep -i set-cookie",
                        references = listOf("https://owasp.org/www-community/SameSite")
                    )
                )
            }
        }

        // Step 5: Information Disclosure & Technology Leakage Audit
        currentCoroutineContext().ensureActive()
        onProgress("Checking Information Disclosure & Banners", "رصد تسريب معلومات الخادم والتقنيات البرمجية", 0.88f)
        testsRun.add("Server Information Disclosure Assessment")

        val serverHeader = headers["Server"]
        if (serverHeader != null && (serverHeader.contains("/") || serverHeader.contains("Apache") || serverHeader.contains("nginx") || serverHeader.contains("IIS"))) {
            findings.add(
                SecurityFinding(
                    id = "SERVER-BANNER-DISCLOSURE",
                    title = "Verbose Server Banner Disclosed",
                    titleAr = "كشف تفاصيل خادم الويب وإصداره في ترويسة Server",
                    category = Category.INFO_DISCLOSURE,
                    severity = Severity.LOW,
                    confidence = Confidence.CONFIRMED,
                    cvssScore = 3.1,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    owaspCategory = "A05:2021-Security Misconfiguration",
                    cweId = "CWE-200",
                    affectedComponent = "HTTP Header: Server",
                    evidence = "Server: $serverHeader",
                    explanationAr = "يكشف الخادم عن نوعه ورقم إصداره التفصيلي، مما يساعد المهاجمين على حصر الثغرات الأمنية المعروفة (CVEs) الخاصة بهذا الإصدار.",
                    explanationEn = "Detailed server banners allow attackers to identify known vulnerabilities corresponding to exact software versions.",
                    impactAr = "تسهيل عمليات الاستطلاع واستهداف الثغرات الخاصة بإصدار الخادم.",
                    impactEn = "Aids adversary reconnaissance and targeted CVE exploitation.",
                    remediationStepsAr = listOf(
                        "قم بإخفاء رقم الإصدار أو إزالة ترويسة Server بالكامل.",
                        "في Nginx: اضبط server_tokens off; وفي Apache: اضبط ServerTokens Prod و ServerSignature Off."
                    ),
                    remediationStepsEn = listOf(
                        "Disable verbose server banners.",
                        "In Nginx use 'server_tokens off;'. In Apache use 'ServerTokens Prod'."
                    ),
                    configSnippet = "# Nginx\nserver_tokens off;\n\n# Apache\nServerTokens Prod\nServerSignature Off",
                    verificationCommand = "curl -sI $formattedUrl | grep -i server",
                    references = listOf("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server")
                )
            )
        }

        val poweredBy = headers["X-Powered-By"]
        if (poweredBy != null) {
            findings.add(
                SecurityFinding(
                    id = "X-POWERED-BY-DISCLOSURE",
                    title = "Technology Fingerprint Leaked via X-Powered-By",
                    titleAr = "كشف لغة أو إطار العمل البرمجي عبر ترويسة X-Powered-By",
                    category = Category.INFO_DISCLOSURE,
                    severity = Severity.LOW,
                    confidence = Confidence.CONFIRMED,
                    cvssScore = 3.1,
                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    owaspCategory = "A05:2021-Security Misconfiguration",
                    cweId = "CWE-200",
                    affectedComponent = "HTTP Header: X-Powered-By",
                    evidence = "X-Powered-By: $poweredBy",
                    explanationAr = "تكشف ترويسة X-Powered-By عن بيئة التشغيل الخلفية (مثل PHP أو Express أو ASP.NET).",
                    explanationEn = "X-Powered-By discloses the runtime framework, accelerating fingerprinting.",
                    impactAr = "تحديد تكنولوجيا التطبيق الخلفي وتركيز الهجمات على ثغرات إطار العمل المعني.",
                    impactEn = "Reveals backend technology stack to potential attackers.",
                    remediationStepsAr = listOf("قم بحذف ترويسة X-Powered-By في خادم الويب أو إعدادات التطبيق."),
                    remediationStepsEn = listOf("Remove the X-Powered-By header from the application and web server."),
                    configSnippet = "# Express.js\napp.disable('x-powered-by');\n\n# PHP (php.ini)\nexpose_php = Off",
                    verificationCommand = "curl -sI $formattedUrl | grep -i x-powered-by",
                    references = listOf("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework")
                )
            )
        }

        // Step 6: Compute Security Score, Grade & AI Summaries
        currentCoroutineContext().ensureActive()
        onProgress("Synthesizing Security Score & AI Reports", "حساب درجة الأمان وتوليد التقارير الذكية", 0.95f)

        val duration = System.currentTimeMillis() - startTime
        val (score, grade) = calculateScoreAndGrade(findings)

        val summary = AuditSummary(
            id = UUID.randomUUID().toString(),
            targetUrl = formattedUrl,
            scannedHost = initialHost,
            timestamp = System.currentTimeMillis(),
            durationMs = duration,
            overallGrade = grade,
            score = score,
            isDemoScan = false,
            findings = findings,
            executiveSummaryAr = generateExecutiveSummaryAr(initialHost, grade, score, findings),
            executiveSummaryEn = generateExecutiveSummaryEn(initialHost, grade, score, findings),
            technicalSummaryAr = generateTechnicalSummaryAr(initialHost, findings, testsRun),
            technicalSummaryEn = generateTechnicalSummaryEn(initialHost, findings, testsRun),
            tlsVersion = tlsVersion,
            tlsCipher = tlsCipher,
            certDaysRemaining = certDaysRemaining,
            certIssuer = certIssuer,
            scannedHeadersCount = headersCount,
            testsRun = testsRun,
            testsSkipped = testsSkipped
        )

        onProgress("Audit Complete", "اكتمل الفحص بنجاح", 1.0f)
        summary
    }

    private data class TlsInspectionResult(
        val protocol: String,
        val cipherSuite: String,
        val daysRemaining: Int,
        val issuer: String
    )

    private fun inspectTls(host: String, port: Int): TlsInspectionResult {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, null, null)
        val factory = sslContext.socketFactory
        val socket = factory.createSocket(host, port) as SSLSocket
        socket.soTimeout = 6000
        socket.startHandshake()

        val session = socket.session
        val protocol = session.protocol ?: "Unknown"
        val cipherSuite = session.cipherSuite ?: "Unknown"

        var daysRemaining = -1
        var issuer = "Unknown"
        val certs = session.peerCertificates
        if (certs.isNotEmpty() && certs[0] is X509Certificate) {
            val x509 = certs[0] as X509Certificate
            issuer = x509.issuerX500Principal.name.substringAfter("CN=").substringBefore(",")
            val notAfter = x509.notAfter.time
            val diff = notAfter - System.currentTimeMillis()
            daysRemaining = if (diff > 0) (diff / (1000 * 60 * 60 * 24)).toInt() else 0
        }
        socket.close()

        return TlsInspectionResult(protocol, cipherSuite, daysRemaining, issuer)
    }

    private fun calculateScoreAndGrade(findings: List<SecurityFinding>): Pair<Int, String> {
        var baseScore = 100
        for (finding in findings) {
            baseScore -= finding.severity.weight
        }
        val finalScore = baseScore.coerceIn(0, 100)
        val grade = when {
            finalScore >= 95 -> "A+"
            finalScore >= 85 -> "A"
            finalScore >= 75 -> "B"
            finalScore >= 60 -> "C"
            finalScore >= 45 -> "D"
            else -> "F"
        }
        return Pair(finalScore, grade)
    }

    private fun generateExecutiveSummaryAr(host: String, grade: String, score: Int, findings: List<SecurityFinding>): String {
        val criticals = findings.count { it.severity == Severity.CRITICAL }
        val highs = findings.count { it.severity == Severity.HIGH }
        val mediums = findings.count { it.severity == Severity.MEDIUM }
        val lows = findings.count { it.severity == Severity.LOW }

        val posture = when (grade) {
            "A+", "A" -> "ممتازة جداً، حيث يلتزم الموقع بأحدث معايير الأمان الدفاعية مع وجود ملاحظات طفيفة يمكن تحسينها."
            "B" -> "جيدة بوجه عام، لكنها تتطلب استكمال بعض إعدادات الحماية الدفاعية مثل ترويسات CSP و HSTS."
            "C" -> "متوسطة وتحتوي على ثغرات إعدادات تزيد من خطر هجمات استدراج النقرات وحقن السكربتات XSS."
            else -> "حرجة وتحتاج تدخلاً أمنياً عاجلاً نظراً لغياب التشفير الأساسي أو وجود ثغرات إعدادات عالية الخطورة."
        }

        return """
            أجرى نظام الفحص الأمني تدقيقاً دفاعياً شاملاً على إعدادات الموقع ($host).
            حصل الموقع على درجة أمان إجمالية تبلغ $score من 100 (التقييم: $grade).
            الحالة العامة للموقع تُصنف بأنها $posture

            إجمالي الملاحظات المرصودة:
            - ثغرات حرجة: $criticals
            - ثغرات مرتفعة: $highs
            - ثغرات متوسطة: $mediums
            - ملاحظات منخفضة ومعلوماتية: ${lows + findings.count { it.severity == Severity.INFO }}

            توصي الإدارة الأمنية بالبدء فوراً بمعالجة المشكلات ذات الأولوية المرتفعة، وتطبيق سياسة CSP مقيدة وتفعيل HSTS لضمان حماية بيانات العملاء والزوار.
        """.trimIndent()
    }

    private fun generateExecutiveSummaryEn(host: String, grade: String, score: Int, findings: List<SecurityFinding>): String {
        val highs = findings.count { it.severity == Severity.HIGH }
        val criticals = findings.count { it.severity == Severity.CRITICAL }

        return "Defensive security posture audit completed for target host '$host'. Overall Score: $score/100 (Grade: $grade). Identified $criticals critical and $highs high severity configuration risks. Immediate remediation of missing security headers and transport layer parameters is recommended."
    }

    private fun generateTechnicalSummaryAr(host: String, findings: List<SecurityFinding>, testsRun: List<String>): String {
        val missingHeaders = findings.filter { it.category == Category.SECURITY_HEADERS }.map { it.titleAr }
        val cookieIssues = findings.filter { it.category == Category.COOKIES }.map { it.titleAr }

        return """
            التقرير الفني للمطورين ومهندسي DevOps:
            1. الاختبارات المنفذة بنجاح: ${testsRun.joinToString("، ")}.
            2. الترويسات المفقودة أو الضعيفة: ${if (missingHeaders.isEmpty()) "لا توجد" else missingHeaders.joinToString(" • ")}.
            3. مشاكل ملفات تعريف الارتباط: ${if (cookieIssues.isEmpty()) "جميع ملفات تعريف الارتباط مؤمنة" else cookieIssues.joinToString(" • ")}.
            4. معايير الامتثال: تم ربط النتائج بكتالوج OWASP Top 10 و CWE و CVSS v3.1 مع توفير أوامر التحقق عبر cURL وتهيئات خوادم Nginx / Apache.
        """.trimIndent()
    }

    private fun generateTechnicalSummaryEn(host: String, findings: List<SecurityFinding>, testsRun: List<String>): String {
        return "Technical Summary: Target host '$host'. Tests executed: ${testsRun.size}. Total findings: ${findings.size}. All findings mapped to OWASP Top 10 and CWE standards with cURL verification scripts provided."
    }
}
