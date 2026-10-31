package com.example

import com.example.ai.SecurityAiAdvisor
import com.example.data.AuditRepository
import com.example.demo.DemoScenarios
import com.example.model.AuditSummary
import com.example.model.Category
import com.example.model.Confidence
import com.example.model.SecurityFinding
import com.example.model.Severity
import com.example.reporting.ReportExporter
import com.example.security.SsrfGuard
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SecurityAuditorUnitTest {

    @Test
    fun `test ssrf guard blocks loopback address`() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val result = SsrfGuard.validateIpAddress(loopback)
        assertTrue(result is SsrfGuard.ValidationResult.Blocked)
    }

    @Test
    fun `test ssrf guard blocks private class A, B, C addresses`() {
        val classA = InetAddress.getByName("10.10.1.1")
        val classB = InetAddress.getByName("172.16.5.10")
        val classC = InetAddress.getByName("192.168.1.100")

        assertTrue(SsrfGuard.validateIpAddress(classA) is SsrfGuard.ValidationResult.Blocked)
        assertTrue(SsrfGuard.validateIpAddress(classB) is SsrfGuard.ValidationResult.Blocked)
        assertTrue(SsrfGuard.validateIpAddress(classC) is SsrfGuard.ValidationResult.Blocked)
    }

    @Test
    fun `test ssrf guard blocks cloud metadata address`() {
        val metadataIp = InetAddress.getByName("169.254.169.254")
        val result = SsrfGuard.validateIpAddress(metadataIp)
        assertTrue(result is SsrfGuard.ValidationResult.Blocked)
    }

    @Test
    fun `test ssrf guard blocks empty or invalid url formats`() {
        val emptyCheck = SsrfGuard.validateTargetUrl("")
        assertTrue(emptyCheck is SsrfGuard.ValidationResult.Blocked)

        val ftpCheck = SsrfGuard.validateTargetUrl("ftp://files.example.com")
        assertTrue(ftpCheck is SsrfGuard.ValidationResult.Blocked)

        val localhostCheck = SsrfGuard.validateTargetUrl("http://localhost:8080")
        assertTrue(localhostCheck is SsrfGuard.ValidationResult.Blocked)
    }

    @Test
    fun `test redirect scope enforcement`() {
        // Strict scope: subdomains disallowed
        assertFalse(SsrfGuard.isRedirectAllowed("example.com", "https://evil.com/login", strictHostOnly = true))
        assertFalse(SsrfGuard.isRedirectAllowed("example.com", "https://sub.example.com", strictHostOnly = true))
        assertTrue(SsrfGuard.isRedirectAllowed("example.com", "https://example.com/checkout", strictHostOnly = true))

        // Subdomain scope allowed:
        assertTrue(SsrfGuard.isRedirectAllowed("example.com", "https://auth.example.com", strictHostOnly = false))
        assertFalse(SsrfGuard.isRedirectAllowed("example.com", "https://attacker.org", strictHostOnly = false))
    }

    @Test
    fun `test json serialization and deserialization of audit summary`() {
        val demo = DemoScenarios.getEcommerceDemo()
        val json = AuditRepository.serializeSummaryToJson(demo)

        assertNotNull(json)
        assertTrue(json.contains("demo-ecommerce-store.example.com"))

        val restored = AuditRepository.deserializeSummaryFromJson(json)
        assertNotNull(restored)
        assertEquals(demo.id, restored!!.id)
        assertEquals(demo.score, restored.score)
        assertEquals(demo.overallGrade, restored.overallGrade)
        assertEquals(demo.findings.size, restored.findings.size)
        assertEquals(demo.findings[0].id, restored.findings[0].id)
    }

    @Test
    fun `test html report exporter contains critical security sections`() {
        val demo = DemoScenarios.getEcommerceDemo()
        val html = ReportExporter.generateHtmlReport(demo)

        assertNotNull(html)
        assertTrue(html.contains("<!DOCTYPE html>"))
        assertTrue(html.contains("AI Web Security Auditor"))
        assertTrue(html.contains("demo-ecommerce-store.example.com"))
        assertTrue(html.contains("DEMO DATA"))
        assertTrue(html.contains("Executive Summary"))
    }

    @Test
    fun `test ai advisor generates post-fix checklist and responsible disclosure`() = runBlocking<Unit> {
        val demo = DemoScenarios.getEcommerceDemo()
        val checklist = SecurityAiAdvisor.generatePostFixChecklist(demo.findings)

        assertTrue(checklist.isNotEmpty())
        assertTrue(checklist.any { it.testCommand.contains("curl") })

        val disclosure = SecurityAiAdvisor.generateResponsibleDisclosure(demo)
        assertNotNull(disclosure)
        assertTrue(disclosure.subject.contains(demo.scannedHost))
        assertTrue(disclosure.bodyMarkdown.contains("Responsible Disclosure"))
    }

    @Test
    fun `test hardened bank demo has perfect A plus grade`() {
        val bankDemo = DemoScenarios.getHardenedBankingDemo()
        assertEquals("A+", bankDemo.overallGrade)
        assertEquals(100, bankDemo.score)
        assertEquals(0, bankDemo.criticalCount)
        assertEquals(0, bankDemo.highCount)
        assertTrue(bankDemo.isDemoScan)
    }
}
