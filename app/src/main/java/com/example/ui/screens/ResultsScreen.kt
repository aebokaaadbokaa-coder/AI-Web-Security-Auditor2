package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.AuditSummary
import com.example.model.SecurityFinding
import com.example.model.Severity
import com.example.reporting.ReportExporter
import com.example.ui.theme.CyberCyan
import com.example.ui.theme.CyberCrimson
import com.example.ui.theme.CyberEmerald
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityInfo
import com.example.ui.theme.SeverityLow
import com.example.ui.theme.SeverityMedium
import com.example.ui.viewmodel.AuditorViewModel

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ResultsScreen(
    viewModel: AuditorViewModel,
    modifier: Modifier = Modifier
) {
    val summary by viewModel.currentSummary.collectAsState()
    val isEnglish by viewModel.isEnglish.collectAsState()
    val selectedFinding by viewModel.selectedFinding.collectAsState()
    val context = LocalContext.current

    var selectedSeverityFilter by remember { mutableStateOf<Severity?>(null) }
    var searchQuery by remember { mutableStateOf("") }

    if (summary == null) {
        Box(
            modifier = modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.outline,
                    modifier = Modifier.size(64.dp)
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = if (isEnglish) "No scan results available yet." else "لا توجد نتائج فحص بعد.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 14.sp
                )
            }
        }
        return
    }

    val s = summary!!

    val filteredFindings = s.findings.filter { finding ->
        (selectedSeverityFilter == null || finding.severity == selectedSeverityFilter) &&
                (searchQuery.isBlank() ||
                        finding.title.contains(searchQuery, ignoreCase = true) ||
                        finding.titleAr.contains(searchQuery, ignoreCase = true) ||
                        finding.cweId.contains(searchQuery, ignoreCase = true) ||
                        finding.owaspCategory.contains(searchQuery, ignoreCase = true))
    }

    val gradeColor = when (s.overallGrade) {
        "A+", "A" -> CyberEmerald
        "B" -> Color(0xFF76FF03)
        "C" -> Color(0xFFFFD600)
        "D" -> Color(0xFFFF9100)
        else -> CyberCrimson
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(8.dp))

            // Demo Warning if applicable
            if (s.isDemoScan) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(Color(0xFFE65100))
                        .padding(vertical = 6.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (isEnglish) "⚠️ DEMO AUDIT DATA — SIMULATED TARGET ⚠️" else "⚠️ بيانات فحص تجريبية — هدف محاكى ⚠️",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            // Score & Grade Card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("score_hero_card"),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = s.scannedHost,
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = if (isEnglish) "Overall Security Posture" else "التقييم الأمني الإجمالي للموقع",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        // Grade Badge
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(12.dp))
                                .background(gradeColor.copy(alpha = 0.15f))
                                .border(2.dp, gradeColor, RoundedCornerShape(12.dp))
                                .padding(horizontal = 16.dp, vertical = 6.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text(
                                    text = s.overallGrade,
                                    fontSize = 28.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    color = gradeColor
                                )
                                Text(
                                    text = "${s.score}/100",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    // Host & TLS Info Strip
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(Color(0xFF091222))
                            .padding(10.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text(text = "TLS Version", fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(text = s.tlsVersion, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
                        }
                        Column {
                            Text(text = if (isEnglish) "Cert Expiry" else "صلاحية الشهادة", fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(
                                text = if (s.certDaysRemaining >= 0) "${s.certDaysRemaining}d" else "N/A",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (s.certDaysRemaining in 0..14) CyberCrimson else CyberEmerald
                            )
                        }
                        Column {
                            Text(text = if (isEnglish) "Headers Inspected" else "الترويسات", fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(text = "${s.scannedHeadersCount}", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
                        }
                        IconButton(
                            onClick = { ReportExporter.shareReport(context, s) },
                            modifier = Modifier.size(28.dp).testTag("share_summary_button")
                        ) {
                            Icon(imageVector = Icons.Default.Share, contentDescription = "Share", tint = CyberCyan, modifier = Modifier.size(18.dp))
                        }
                    }
                }
            }
        }

        // Search & Severity Filter Chips
        item {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("findings_search_input"),
                placeholder = { Text(if (isEnglish) "Filter by title, CWE, OWASP..." else "بحث في الثغرات والترويسات...") },
                leadingIcon = {
                    Icon(imageVector = Icons.Default.Search, contentDescription = "Search", tint = CyberCyan)
                },
                singleLine = true,
                shape = RoundedCornerShape(8.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = CyberCyan,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline
                )
            )

            Spacer(modifier = Modifier.height(8.dp))

            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                FilterChip(
                    selected = selectedSeverityFilter == null,
                    onClick = { selectedSeverityFilter = null },
                    label = { Text(if (isEnglish) "All (${s.findings.size})" else "الكل (${s.findings.size})", fontSize = 11.sp) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = CyberCyan,
                        selectedLabelColor = Color.Black
                    )
                )
                if (s.criticalCount > 0) {
                    FilterChip(
                        selected = selectedSeverityFilter == Severity.CRITICAL,
                        onClick = { selectedSeverityFilter = if (selectedSeverityFilter == Severity.CRITICAL) null else Severity.CRITICAL },
                        label = { Text(if (isEnglish) "Critical (${s.criticalCount})" else "حرجة (${s.criticalCount})", fontSize = 11.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = SeverityCritical,
                            selectedLabelColor = Color.White
                        )
                    )
                }
                if (s.highCount > 0) {
                    FilterChip(
                        selected = selectedSeverityFilter == Severity.HIGH,
                        onClick = { selectedSeverityFilter = if (selectedSeverityFilter == Severity.HIGH) null else Severity.HIGH },
                        label = { Text(if (isEnglish) "High (${s.highCount})" else "مرتفعة (${s.highCount})", fontSize = 11.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = SeverityHigh,
                            selectedLabelColor = Color.White
                        )
                    )
                }
                if (s.mediumCount > 0) {
                    FilterChip(
                        selected = selectedSeverityFilter == Severity.MEDIUM,
                        onClick = { selectedSeverityFilter = if (selectedSeverityFilter == Severity.MEDIUM) null else Severity.MEDIUM },
                        label = { Text(if (isEnglish) "Medium (${s.mediumCount})" else "متوسطة (${s.mediumCount})", fontSize = 11.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = SeverityMedium,
                            selectedLabelColor = Color.Black
                        )
                    )
                }
                if (s.lowCount > 0) {
                    FilterChip(
                        selected = selectedSeverityFilter == Severity.LOW,
                        onClick = { selectedSeverityFilter = if (selectedSeverityFilter == Severity.LOW) null else Severity.LOW },
                        label = { Text(if (isEnglish) "Low (${s.lowCount})" else "منخفضة (${s.lowCount})", fontSize = 11.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = SeverityLow,
                            selectedLabelColor = Color.Black
                        )
                    )
                }
            }
        }

        // Findings List
        if (filteredFindings.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (isEnglish) "No findings match the current filter." else "لا توجد نتائج تطابق خيارات التصفية.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            items(filteredFindings, key = { it.id }) { finding ->
                FindingListItemCard(
                    finding = finding,
                    isEnglish = isEnglish,
                    onClick = { viewModel.selectFinding(finding) }
                )
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }

    // Modal Detail Dialog
    selectedFinding?.let { finding ->
        FindingDetailDialog(
            finding = finding,
            isEnglish = isEnglish,
            onDismiss = { viewModel.selectFinding(null) }
        )
    }
}

@Composable
fun FindingListItemCard(
    finding: SecurityFinding,
    isEnglish: Boolean,
    onClick: () -> Unit
) {
    val severityColor = when (finding.severity) {
        Severity.CRITICAL -> SeverityCritical
        Severity.HIGH -> SeverityHigh
        Severity.MEDIUM -> SeverityMedium
        Severity.LOW -> SeverityLow
        Severity.INFO -> SeverityInfo
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .clickable { onClick() }
            .testTag("finding_item_${finding.id}"),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(severityColor)
                            .padding(horizontal = 8.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = if (isEnglish) finding.severity.labelEn else finding.severity.labelAr,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.Black
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = finding.cweId,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = CyberCyan
                    )
                }

                Text(
                    text = "CVSS ${finding.cvssScore ?: "N/A"}",
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = if (isEnglish) finding.title else finding.titleAr,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = finding.affectedComponent,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = finding.owaspCategory,
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = if (isEnglish) "View Fix & Evidence" else "التفاصيل وحل المشكلة",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = CyberCyan
                    )
                    Icon(
                        imageVector = Icons.Default.ChevronRight,
                        contentDescription = "Open",
                        tint = CyberCyan,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }
    }
}
