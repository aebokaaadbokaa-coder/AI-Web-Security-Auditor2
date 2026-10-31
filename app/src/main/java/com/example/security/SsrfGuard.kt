package com.example.security

import java.net.InetAddress
import java.net.URI

object SsrfGuard {

    sealed class ValidationResult {
        object Allowed : ValidationResult()
        data class Blocked(val reasonAr: String, val reasonEn: String) : ValidationResult()
    }

    /**
     * Checks if a target URI passes strict SSRF checks and matches permitted schemes and scopes.
     */
    fun validateTargetUrl(rawUrl: String): ValidationResult {
        val trimmed = rawUrl.trim()
        if (trimmed.isEmpty()) {
            return ValidationResult.Blocked("يرجى إدخال رابط صالح", "Target URL is empty")
        }

        val uri = try {
            val formatted = if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
                "https://$trimmed"
            } else {
                trimmed
            }
            URI.create(formatted)
        } catch (e: Exception) {
            return ValidationResult.Blocked("صيغة الرابط غير صحيحة", "Invalid URL format: ${e.message}")
        }

        val scheme = uri.scheme?.lowercase() ?: ""
        if (scheme != "http" && scheme != "https") {
            return ValidationResult.Blocked(
                "البروتوكول غير مدعوم. يدعم الفحص بروتوكولات HTTP و HTTPS فقط",
                "Unsupported scheme '$scheme'. Only HTTP and HTTPS are permitted."
            )
        }

        val host = uri.host ?: return ValidationResult.Blocked("لم يتم العثور على اسم نطاق في الرابط", "Hostname is missing")
        val cleanHost = host.lowercase().trim()

        // 1. Check prohibited hostname strings
        if (isDisallowedHostname(cleanHost)) {
            return ValidationResult.Blocked(
                "محظور أمنياً: لا يُسمح بفحص المضيف المحلي (localhost) أو النطاقات الداخلية",
                "Security Block: Localhost and internal development hosts are strictly prohibited (SSRF Defense)."
            )
        }

        // 2. Resolve DNS and check all resolved IP addresses
        return try {
            val addresses = InetAddress.getAllByName(cleanHost)
            if (addresses.isEmpty()) {
                ValidationResult.Blocked("تعذر ترجمة النطاق عبر DNS", "DNS resolution returned no addresses for host")
            } else {
                for (address in addresses) {
                    val ipCheck = validateIpAddress(address)
                    if (ipCheck is ValidationResult.Blocked) {
                        return ipCheck
                    }
                }
                ValidationResult.Allowed
            }
        } catch (e: Exception) {
            ValidationResult.Blocked(
                "فشل الاتصال بـ DNS للتحقق من النطاق: ${e.localizedMessage ?: "نطاق غير معروف"}",
                "DNS lookup failed: ${e.localizedMessage ?: "Unknown host"}"
            )
        }
    }

    /**
     * Inspects an IP address to ensure it is not a private, loopback, or cloud-metadata IP.
     */
    fun validateIpAddress(address: InetAddress): ValidationResult {
        if (address.isLoopbackAddress) {
            return ValidationResult.Blocked(
                "محظور: عنوان حلقة مغلقة محلي (Loopback / 127.0.0.1)",
                "Blocked: Loopback address detected (${address.hostAddress})"
            )
        }

        if (address.isAnyLocalAddress || address.isLinkLocalAddress || address.isSiteLocalAddress) {
            return ValidationResult.Blocked(
                "محظور أمنياً: عنوان شبكة داخلية خاصة (RFC1918 / Link-Local)",
                "Blocked: Private network IP range detected (${address.hostAddress})"
            )
        }

        if (address.isMulticastAddress) {
            return ValidationResult.Blocked(
                "محظور: عنوان بث متعدد (Multicast)",
                "Blocked: Multicast IP address detected"
            )
        }

        val ipStr = address.hostAddress ?: ""

        // Check AWS/GCP/Azure link-local metadata service (169.254.169.254) and range 169.254.0.0/16
        if (ipStr.startsWith("169.254.")) {
            return ValidationResult.Blocked(
                "محظور أمنياً: عنوان خدمة بيانات التعريف السحابية الحساسة (Cloud Metadata 169.254.x.x)",
                "Blocked: Cloud metadata IP range detected (SSRF Defense)"
            )
        }

        // Check Carrier Grade NAT: 100.64.0.0/10 (100.64.x.x to 100.127.x.x)
        if (ipStr.startsWith("100.")) {
            val parts = ipStr.split(".")
            if (parts.size >= 2) {
                val secondOctet = parts[1].toIntOrNull() ?: 0
                if (secondOctet in 64..127) {
                    return ValidationResult.Blocked(
                        "محظور: عنوان شبكة خاصة بالمزودين (CGNAT 100.64.0.0/10)",
                        "Blocked: Shared carrier network IP detected (${address.hostAddress})"
                    )
                }
            }
        }

        // 0.0.0.0 and broadcast
        if (ipStr == "0.0.0.0" || ipStr == "255.255.255.255") {
            return ValidationResult.Blocked(
                "محظور: عنوان غير صالح للشبكة العامة",
                "Blocked: Non-routable broadcast or zero IP"
            )
        }

        return ValidationResult.Allowed
    }

    private fun isDisallowedHostname(host: String): Boolean {
        val lower = host.lowercase()
        return lower == "localhost" ||
                lower == "127.0.0.1" ||
                lower == "::1" ||
                lower.endsWith(".localhost") ||
                lower.endsWith(".local") ||
                lower.endsWith(".internal") ||
                lower.endsWith(".corp") ||
                lower.endsWith(".lan") ||
                lower == "metadata.google.internal" ||
                lower == "instance-data"
    }

    /**
     * Ensures redirects stay within the authorized target host.
     */
    fun isRedirectAllowed(initialHost: String, redirectUrl: String, strictHostOnly: Boolean): Boolean {
        return try {
            val redirectUri = URI.create(redirectUrl)
            val redirectHost = redirectUri.host?.lowercase() ?: return false
            val initial = initialHost.lowercase()

            if (strictHostOnly) {
                redirectHost == initial
            } else {
                redirectHost == initial || redirectHost.endsWith(".$initial")
            }
        } catch (_: Exception) {
            false
        }
    }
}
