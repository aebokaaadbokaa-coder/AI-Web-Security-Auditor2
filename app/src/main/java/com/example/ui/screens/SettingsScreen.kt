package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Gavel
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.theme.CyberCyan
import com.example.ui.theme.CyberEmerald
import com.example.ui.viewmodel.AuditorViewModel

@Composable
fun SettingsScreen(viewModel: AuditorViewModel, modifier: Modifier = Modifier) {
    val isEnglish by viewModel.isEnglish.collectAsState()

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(8.dp))

            // App Identity & Version Card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("settings_identity_card"),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(MaterialTheme.colorScheme.primaryContainer),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(imageVector = Icons.Default.Security, contentDescription = "Security", tint = CyberCyan)
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = "AI Web Security Auditor",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "v1.0.0 (Build release-tested) • Jetpack Compose & Kotlin",
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    // Language Toggle
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (isEnglish) "Interface Language / لغة الواجهة" else "لغة الواجهة / Interface Language",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        OutlinedButton(
                            onClick = { viewModel.toggleLanguage() },
                            shape = RoundedCornerShape(20.dp),
                            modifier = Modifier.testTag("settings_lang_button")
                        ) {
                            Text(text = if (isEnglish) "Switch to العربية" else "الانتقال إلى English", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        // SSRF Guard Policy Details
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(imageVector = Icons.Default.Policy, contentDescription = "Policy", tint = CyberEmerald)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isEnglish) "SSRF & Scope Enforcement Policy" else "سياسة الحماية الصارمة من ثغرات SSRF",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = CyberEmerald
                        )
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = if (isEnglish)
                            "To ensure ethical and safe operation, the scanning engine validates DNS resolutions against RFC1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopbacks (127.0.0.1, ::1), carrier-grade NAT (100.64.0.0/10), and cloud metadata endpoints (169.254.169.254, metadata.google.internal). Any target attempting to redirect to an internal network is immediately aborted."
                        else
                            "لضمان السلامة التامة والامتثال للمعايير، يتحقق محرك الفحص من كافة عناوين IP قبل الاتصال ويحظر تلقائياً:\n• الشبكات الخاصة (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)\n• عناوين الحلقة المغلقة (127.0.0.1, localhost)\n• خدمات البيانات السحابية الحساسة (169.254.169.254)\n• يمنع المحرك أي إعادة توجيه (Redirect) تقود لخارج النطاق المصرح به.",
                        fontSize = 12.sp,
                        lineHeight = 18.sp,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }

        // Standards & References
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(imageVector = Icons.Default.Gavel, contentDescription = "Legal", tint = CyberCyan)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isEnglish) "Standards & Frameworks" else "المعايير والمراجع المعتمدة في الفحص",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = CyberCyan
                        )
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = "• OWASP Top 10 (2021) - A05: Security Misconfiguration\n" +
                                "• OWASP Application Security Verification Standard (ASVS v4.0)\n" +
                                "• OWASP Web Security Testing Guide (WSTG v4.2)\n" +
                                "• Common Weakness Enumeration (CWE) & CVSS v3.1 Scoring\n" +
                                "• RFC 6797: HTTP Strict Transport Security (HSTS)\n" +
                                "• W3C Content Security Policy Level 3\n" +
                                "• Mozilla Web Security Guidelines & Server Hardening Best Practices",
                        fontSize = 12.sp,
                        lineHeight = 20.sp,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }

        // Ethical Usage Notice
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF2A1500)),
                border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFFF9800))
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = if (isEnglish) "Notice on Ethical & Authorized Use" else "إشعار الاستخدام الأخلاقي والمصرح به",
                        fontWeight = FontWeight.Bold,
                        fontSize = 13.sp,
                        color = Color(0xFFFFB74D)
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = if (isEnglish)
                            "This application performs purely defensive, non-destructive configuration inspection. It does not exploit vulnerabilities, bypass authentication, or brute force credentials. Always obtain documented authorization before auditing targets you do not personally own."
                        else
                            "هذا التطبيق مخصص حصرياً للتدقيق الدفاعي غير التخريبي وفحص إعدادات الترويسات والتشفير لمساعدة المطورين وأصحاب المواقع على تحصين أنظمتهم. لا يتضمن التطبيق أي هجمات استغلالية أو تخمين كلمات مرور أو تعطيل خدمات. يلتزم المستخدم بالحصول على تفويض كتابي قبل فحص أي نطاق خارجي.",
                        fontSize = 11.sp,
                        lineHeight = 17.sp,
                        color = Color(0xFFFFE0B2)
                    )
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}
