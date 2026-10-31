package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.ScanState
import com.example.model.TargetScope
import com.example.ui.theme.CyberCyan
import com.example.ui.theme.CyberCrimson
import com.example.ui.theme.CyberEmerald
import com.example.ui.theme.SeverityHigh
import com.example.ui.viewmodel.AuditorViewModel

@Composable
fun DashboardScreen(viewModel: AuditorViewModel, modifier: Modifier = Modifier) {
    val targetUrl by viewModel.targetUrl.collectAsState()
    val hasConsent by viewModel.hasConsent.collectAsState()
    val scope by viewModel.scope.collectAsState()
    val isDemoMode by viewModel.isDemoMode.collectAsState()
    val scanState by viewModel.scanState.collectAsState()
    val isEnglish by viewModel.isEnglish.collectAsState()

    val isScanning = scanState is ScanState.Scanning

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(8.dp))
            // Hero Title Card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("dashboard_hero_card"),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
            ) {
                Column(
                    modifier = Modifier.padding(18.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(46.dp)
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(MaterialTheme.colorScheme.primaryContainer),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Shield,
                                    contentDescription = "Shield Icon",
                                    tint = CyberCyan,
                                    modifier = Modifier.size(28.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text(
                                    text = if (isEnglish) "AI Web Security Auditor" else "مدقق أمن الويب الذكي",
                                    style = MaterialTheme.typography.titleLarge,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                Text(
                                    text = if (isEnglish) "Defensive Posture & Standards Audit" else "فحص دفاعي متقدم لمعايير OWASP و TLS",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }

                        // Language Switch Button
                        OutlinedButton(
                            onClick = { viewModel.toggleLanguage() },
                            shape = RoundedCornerShape(20.dp),
                            modifier = Modifier.testTag("lang_toggle_button")
                        ) {
                            Text(text = if (isEnglish) "عربي" else "EN", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    // SSRF Guard active pill
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(Color(0xFF003822))
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = "SSRF Active",
                            tint = CyberEmerald,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isEnglish) "SSRF & Safe Scope Guard: ACTIVE (Loopback & Metadata Blocked)" else "حماية SSRF والنطاق الآمن: نشطة (حظر الشبكات الداخلية والبيانات السحابية)",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = CyberEmerald
                        )
                    }
                }
            }
        }

        // Demo Mode Switch Card
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("demo_mode_card"),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (isDemoMode) Color(0xFF2D1600) else MaterialTheme.colorScheme.surface
                ),
                border = androidx.compose.foundation.BorderStroke(
                    1.dp,
                    if (isDemoMode) Color(0xFFFF9800) else MaterialTheme.colorScheme.outline
                )
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = if (isEnglish) "Demo Mode (Safe Testing Sandbox)" else "وضع البيانات التجريبية (Demo Mode)",
                                fontWeight = FontWeight.Bold,
                                color = if (isDemoMode) Color(0xFFFFB74D) else MaterialTheme.colorScheme.onSurface,
                                fontSize = 15.sp
                            )
                            Text(
                                text = if (isEnglish) "Run simulated audits with pre-packaged realistic targets" else "اختبر الفحص بنماذج واقعية سابقة الإعداد بدون إرسال حزم للإنترنت",
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = isDemoMode,
                            onCheckedChange = { viewModel.setDemoMode(it) },
                            modifier = Modifier.testTag("demo_mode_switch"),
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = Color(0xFFFF9800),
                                checkedTrackColor = Color(0xFF5A2A00)
                            )
                        )
                    }

                    if (isDemoMode) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { viewModel.runEcommerceDemo() },
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("demo_ecommerce_button"),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE65100)),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Text(
                                    text = if (isEnglish) "E-Commerce (Risk C)" else "متجر إلكتروني (درجة C)",
                                    fontSize = 11.sp,
                                    color = Color.White
                                )
                            }
                            Button(
                                onClick = { viewModel.runBankingDemo() },
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("demo_banking_button"),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1B5E20)),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Text(
                                    text = if (isEnglish) "Bank Portal (Grade A+)" else "بوابة بنكية (درجة A+)",
                                    fontSize = 11.sp,
                                    color = Color.White
                                )
                            }
                        }
                    }
                }
            }
        }

        // Live Audit Target Input Card
        if (!isDemoMode) {
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("target_input_card"),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = if (isEnglish) "Target URL for Security Audit" else "رابط الموقع المستهدف للفحص",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Spacer(modifier = Modifier.height(8.dp))

                        OutlinedTextField(
                            value = targetUrl,
                            onValueChange = { viewModel.setTargetUrl(it) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("target_url_input"),
                            placeholder = { Text("https://example.com") },
                            leadingIcon = {
                                Icon(
                                    imageVector = Icons.Default.Language,
                                    contentDescription = "URL Icon",
                                    tint = CyberCyan
                                )
                            },
                            singleLine = true,
                            enabled = !isScanning,
                            shape = RoundedCornerShape(8.dp),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = CyberCyan,
                                unfocusedBorderColor = MaterialTheme.colorScheme.outline
                            )
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        // Target Scope Picker
                        Text(
                            text = if (isEnglish) "Audit Scope" else "نطاق الفحص المصرح به:",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            TargetScope.values().forEach { itemScope ->
                                val selected = scope == itemScope
                                Box(
                                    modifier = Modifier
                                        .weight(1f)
                                        .clip(RoundedCornerShape(8.dp))
                                        .background(if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant)
                                        .border(
                                            1.dp,
                                            if (selected) CyberCyan else MaterialTheme.colorScheme.outline,
                                            RoundedCornerShape(8.dp)
                                        )
                                        .clickable(enabled = !isScanning) { viewModel.setScope(itemScope) }
                                        .padding(vertical = 10.dp, horizontal = 8.dp),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = if (isEnglish) itemScope.labelEn else itemScope.labelAr,
                                        fontSize = 11.sp,
                                        fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                                        color = if (selected) CyberCyan else MaterialTheme.colorScheme.onSurface,
                                        textAlign = TextAlign.Center
                                    )
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        // Legal Authorization Consent Checkbox
                        Row(
                            verticalAlignment = Alignment.Top,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                                .clickable(enabled = !isScanning) { viewModel.setConsent(!hasConsent) }
                                .padding(8.dp)
                        ) {
                            Checkbox(
                                checked = hasConsent,
                                onCheckedChange = { viewModel.setConsent(it) },
                                enabled = !isScanning,
                                modifier = Modifier.testTag("consent_checkbox"),
                                colors = CheckboxDefaults.colors(
                                    checkedColor = CyberEmerald,
                                    uncheckedColor = MaterialTheme.colorScheme.outline
                                )
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = if (isEnglish)
                                    "I confirm that I own this website or have explicit written authorization to perform a non-destructive security audit."
                                else
                                    "أقر وأؤكد بأنني أملك هذا الموقع أو لدي تصريح كتابي وموثق بإجراء فحص أمني دفاعي غير تخريبي.",
                                fontSize = 12.sp,
                                lineHeight = 16.sp,
                                color = if (hasConsent) CyberEmerald else MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }
            }
        }

        // Live Scanning Progress / Error State
        item {
            AnimatedVisibility(visible = scanState !is ScanState.Idle) {
                when (val state = scanState) {
                    is ScanState.Scanning -> {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("scanning_progress_card"),
                            shape = RoundedCornerShape(12.dp),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                            border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan)
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        CircularProgressIndicator(
                                            modifier = Modifier.size(20.dp),
                                            strokeWidth = 2.dp,
                                            color = CyberCyan
                                        )
                                        Spacer(modifier = Modifier.width(10.dp))
                                        Text(
                                            text = if (isEnglish) state.step else state.stepAr,
                                            fontSize = 13.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = CyberCyan
                                        )
                                    }
                                    Text(
                                        text = "${(state.progress * 100).toInt()}%",
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                                Spacer(modifier = Modifier.height(10.dp))
                                LinearProgressIndicator(
                                    progress = { state.progress },
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(6.dp)
                                        .clip(RoundedCornerShape(3.dp)),
                                    color = CyberCyan,
                                    trackColor = MaterialTheme.colorScheme.outline
                                )
                            }
                        }
                    }
                    is ScanState.Error -> {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("scan_error_card"),
                            shape = RoundedCornerShape(12.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF33080F)),
                            border = androidx.compose.foundation.BorderStroke(1.dp, CyberCrimson)
                        ) {
                            Row(
                                modifier = Modifier.padding(14.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Warning,
                                    contentDescription = "Error",
                                    tint = CyberCrimson,
                                    modifier = Modifier.size(24.dp)
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = if (isEnglish) "Audit Blocked / Failed" else "فشل أو حظر الفحص",
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 13.sp,
                                        color = CyberCrimson
                                    )
                                    Text(
                                        text = if (isEnglish) state.messageEn else state.messageAr,
                                        fontSize = 12.sp,
                                        color = Color.White
                                    )
                                }
                            }
                        }
                    }
                    else -> Unit
                }
            }
        }

        // Action Buttons: Start Scan & Stop Scan
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                if (isScanning) {
                    Button(
                        onClick = { viewModel.stopScan() },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(50.dp)
                            .testTag("stop_scan_button"),
                        colors = ButtonDefaults.buttonColors(containerColor = CyberCrimson),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Icon(imageVector = Icons.Default.Stop, contentDescription = "Stop", tint = Color.White)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isEnglish) "Stop Audit" else "إيقاف الفحص الحالي",
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                    }
                } else {
                    Button(
                        onClick = { viewModel.startScan() },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp)
                            .testTag("start_scan_button"),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = CyberCyan,
                            disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant
                        ),
                        shape = RoundedCornerShape(10.dp),
                        enabled = isDemoMode || hasConsent
                    ) {
                        Icon(
                            imageVector = Icons.Default.PlayArrow,
                            contentDescription = "Start",
                            tint = Color(0xFF00222B)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isDemoMode) {
                                if (isEnglish) "Run Demo Audit" else "بدء الفحص التجريبي"
                            } else {
                                if (isEnglish) "Start Security Audit" else "بدء الفحص الأمني الدفاعي"
                            },
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp,
                            color = Color(0xFF00222B)
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}
