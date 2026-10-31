package com.example.ui.screens

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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material.icons.filled.CompareArrows
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.TrendingUp
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import com.example.data.AuditRecordEntity
import com.example.ui.theme.CyberCyan
import com.example.ui.theme.CyberEmerald
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityHigh
import com.example.ui.viewmodel.AuditorViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun HistoryScreen(viewModel: AuditorViewModel, modifier: Modifier = Modifier) {
    val historyList by viewModel.historyList.collectAsState()
    val isEnglish by viewModel.isEnglish.collectAsState()
    val compareFirst by viewModel.compareFirst.collectAsState()
    val compareSecond by viewModel.compareSecond.collectAsState()

    val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(8.dp))

            // History Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(imageVector = Icons.Default.History, contentDescription = "History", tint = CyberCyan)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (isEnglish) "Audit History & Comparison" else "سجل الفحوصات ومقارنة التقدم",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
                Text(
                    text = "${historyList.size} ${if (isEnglish) "scans" else "فحص محفوظ"}",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // Comparison Panel (if both are selected)
        if (compareFirst != null && compareSecond != null) {
            item {
                val f1 = compareFirst!!
                val f2 = compareSecond!!
                val scoreDiff = f2.score - f1.score

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("diff_comparison_card"),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0F1E36)),
                    border = androidx.compose.foundation.BorderStroke(1.dp, CyberCyan)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = if (isEnglish) "Audit Comparison (Diff)" else "مقارنة نتائج الفحصين (Diff)",
                                fontWeight = FontWeight.Bold,
                                color = CyberCyan,
                                fontSize = 14.sp
                            )
                            IconButton(
                                onClick = {
                                    viewModel.selectForComparison("", true)
                                    viewModel.selectForComparison("", false)
                                },
                                modifier = Modifier.size(24.dp)
                            ) {
                                Icon(imageVector = Icons.Default.Delete, contentDescription = "Clear Compare", tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(16.dp))
                            }
                        }

                        Spacer(modifier = Modifier.height(10.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(text = f1.scannedHost, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
                                Text(text = "${f1.overallGrade} (${f1.score}/100)", fontSize = 13.sp, color = CyberCyan)
                            }
                            Icon(imageVector = Icons.Default.ArrowForward, contentDescription = "to", tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            Column {
                                Text(text = f2.scannedHost, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
                                Text(text = "${f2.overallGrade} (${f2.score}/100)", fontSize = 13.sp, color = CyberEmerald)
                            }
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(if (scoreDiff >= 0) Color(0xFF004D2E) else Color(0xFF5A0C16))
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    text = if (scoreDiff >= 0) "+$scoreDiff" else "$scoreDiff",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp,
                                    color = if (scoreDiff >= 0) CyberEmerald else Color.Red
                                )
                            }
                        }
                    }
                }
            }
        }

        if (historyList.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(40.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (isEnglish) "No recorded scans yet. Run an audit to populate history." else "لا توجد فحوصات سابقة. قم بإجراء فحص لإضافته إلى السجل.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 13.sp
                    )
                }
            }
        } else {
            items(historyList, key = { it.id }) { record ->
                HistoryRecordCard(
                    record = record,
                    dateFormatted = dateFormat.format(Date(record.timestamp)),
                    isEnglish = isEnglish,
                    onClick = { viewModel.loadHistoricalScan(record.id) },
                    onDelete = { viewModel.deleteHistoricalScan(record.id) },
                    onSelectCompareA = { viewModel.selectForComparison(record.id, true) },
                    onSelectCompareB = { viewModel.selectForComparison(record.id, false) }
                )
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
fun HistoryRecordCard(
    record: AuditRecordEntity,
    dateFormatted: String,
    isEnglish: Boolean,
    onClick: () -> Unit,
    onDelete: () -> Unit,
    onSelectCompareA: () -> Unit,
    onSelectCompareB: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .clickable { onClick() }
            .testTag("history_card_${record.id}"),
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
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = record.scannedHost,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        text = dateFormatted,
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                // Grade Pill
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(MaterialTheme.colorScheme.primaryContainer)
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = "${record.overallGrade} (${record.score})",
                        fontWeight = FontWeight.Bold,
                        fontSize = 13.sp,
                        color = CyberCyan
                    )
                }

                IconButton(onClick = onDelete, modifier = Modifier.size(32.dp)) {
                    Icon(imageVector = Icons.Default.Delete, contentDescription = "Delete", tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(16.dp))
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Counts & Compare buttons row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (record.criticalCount > 0) {
                        Text(text = "🔥 ${record.criticalCount}", fontSize = 11.sp, color = SeverityCritical, fontWeight = FontWeight.Bold)
                    }
                    if (record.highCount > 0) {
                        Text(text = "⚠️ ${record.highCount}", fontSize = 11.sp, color = SeverityHigh, fontWeight = FontWeight.Bold)
                    }
                    Text(text = "TLS: ${record.tlsVersion}", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }

                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    OutlinedButton(
                        onClick = onSelectCompareA,
                        shape = RoundedCornerShape(6.dp),
                        modifier = Modifier.height(28.dp)
                    ) {
                        Text(text = "قارن A", fontSize = 10.sp)
                    }
                    OutlinedButton(
                        onClick = onSelectCompareB,
                        shape = RoundedCornerShape(6.dp),
                        modifier = Modifier.height(28.dp)
                    ) {
                        Text(text = "قارن B", fontSize = 10.sp)
                    }
                }
            }
        }
    }
}
