package com.example.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.ai.PostFixCheckItem
import com.example.ai.ResponsibleDisclosureDraft
import com.example.ai.SecurityAiAdvisor
import com.example.data.AuditDatabase
import com.example.data.AuditRecordEntity
import com.example.data.AuditRepository
import com.example.demo.DemoScenarios
import com.example.model.AuditSummary
import com.example.model.ScanState
import com.example.model.SecurityFinding
import com.example.model.TargetScope
import com.example.security.SafeAuditorClient
import com.example.security.SsrfGuard
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

enum class AppTab(val labelEn: String, val labelAr: String) {
    DASHBOARD("Auditor", "الفحص الأمني"),
    RESULTS("Findings", "نتائج الفحص"),
    AI_REPORT("AI Advisory", "مستشار الذكاء الاصطناعي"),
    HISTORY("History & Diff", "السجل والمقارنة"),
    SETTINGS("Guidelines", "الضوابط والسياسة")
}

class AuditorViewModel(application: Application) : AndroidViewModel(application) {

    private val repository: AuditRepository
    private val auditorClient = SafeAuditorClient()

    private val _targetUrl = MutableStateFlow("https://example.com")
    val targetUrl: StateFlow<String> = _targetUrl.asStateFlow()

    private val _hasConsent = MutableStateFlow(false)
    val hasConsent: StateFlow<Boolean> = _hasConsent.asStateFlow()

    private val _scope = MutableStateFlow(TargetScope.STRICT_HOST)
    val scope: StateFlow<TargetScope> = _scope.asStateFlow()

    private val _isDemoMode = MutableStateFlow(false)
    val isDemoMode: StateFlow<Boolean> = _isDemoMode.asStateFlow()

    private val _scanState = MutableStateFlow<ScanState>(ScanState.Idle)
    val scanState: StateFlow<ScanState> = _scanState.asStateFlow()

    private val _currentSummary = MutableStateFlow<AuditSummary?>(null)
    val currentSummary: StateFlow<AuditSummary?> = _currentSummary.asStateFlow()

    private val _historyList = MutableStateFlow<List<AuditRecordEntity>>(emptyList())
    val historyList: StateFlow<List<AuditRecordEntity>> = _historyList.asStateFlow()

    private val _activeTab = MutableStateFlow(AppTab.DASHBOARD)
    val activeTab: StateFlow<AppTab> = _activeTab.asStateFlow()

    private val _selectedFinding = MutableStateFlow<SecurityFinding?>(null)
    val selectedFinding: StateFlow<SecurityFinding?> = _selectedFinding.asStateFlow()

    private val _checkItems = MutableStateFlow<List<PostFixCheckItem>>(emptyList())
    val checkItems: StateFlow<List<PostFixCheckItem>> = _checkItems.asStateFlow()

    private val _disclosureDraft = MutableStateFlow<ResponsibleDisclosureDraft?>(null)
    val disclosureDraft: StateFlow<ResponsibleDisclosureDraft?> = _disclosureDraft.asStateFlow()

    private val _isEnglish = MutableStateFlow(false)
    val isEnglish: StateFlow<Boolean> = _isEnglish.asStateFlow()

    // Comparison Mode
    private val _compareFirst = MutableStateFlow<AuditSummary?>(null)
    val compareFirst: StateFlow<AuditSummary?> = _compareFirst.asStateFlow()

    private val _compareSecond = MutableStateFlow<AuditSummary?>(null)
    val compareSecond: StateFlow<AuditSummary?> = _compareSecond.asStateFlow()

    private var scanJob: Job? = null

    init {
        val database = AuditDatabase.getDatabase(application)
        repository = AuditRepository(database.auditDao())
        loadHistory()
    }

    private fun loadHistory() {
        viewModelScope.launch {
            repository.getAuditHistory().collect { list ->
                _historyList.value = list
            }
        }
    }

    fun setTargetUrl(url: String) {
        _targetUrl.value = url
    }

    fun setConsent(consent: Boolean) {
        _hasConsent.value = consent
    }

    fun setScope(scope: TargetScope) {
        _scope.value = scope
    }

    fun setDemoMode(isDemo: Boolean) {
        _isDemoMode.value = isDemo
    }

    fun setActiveTab(tab: AppTab) {
        _activeTab.value = tab
    }

    fun toggleLanguage() {
        _isEnglish.value = !_isEnglish.value
    }

    fun selectFinding(finding: SecurityFinding?) {
        _selectedFinding.value = finding
    }

    fun startScan() {
        if (!_hasConsent.value && !_isDemoMode.value) {
            _scanState.value = ScanState.Error(
                messageAr = "يجب تأكيد إقرار التصريح بفحص الموقع قبل البدء لحماية النطاقات والامتثال القانوني.",
                messageEn = "You must confirm authorization to audit this target before starting."
            )
            return
        }

        if (_isDemoMode.value) {
            runEcommerceDemo()
            return
        }

        val rawUrl = _targetUrl.value.trim()
        val ssrfPreCheck = SsrfGuard.validateTargetUrl(rawUrl)
        if (ssrfPreCheck is SsrfGuard.ValidationResult.Blocked) {
            _scanState.value = ScanState.Error(
                messageAr = ssrfPreCheck.reasonAr,
                messageEn = ssrfPreCheck.reasonEn,
                isSsrfBlocked = true
            )
            return
        }

        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            _scanState.value = ScanState.Scanning("Starting Engine...", "بدء تشغيل محرك الفحص الأمني...", 0.05f)

            try {
                val summary = auditorClient.auditTarget(rawUrl, _scope.value) { stepEn, stepAr, progress ->
                    _scanState.value = ScanState.Scanning(stepEn, stepAr, progress)
                }

                _currentSummary.value = summary
                _scanState.value = ScanState.Success(summary)

                // Save to Room DB
                repository.saveAudit(summary)

                // Prepare AI Checklist and Disclosure
                _checkItems.value = SecurityAiAdvisor.generatePostFixChecklist(summary.findings)
                _disclosureDraft.value = SecurityAiAdvisor.generateResponsibleDisclosure(summary)

                // Switch to Results Tab
                _activeTab.value = AppTab.RESULTS

            } catch (e: SecurityException) {
                _scanState.value = ScanState.Error(
                    messageAr = e.localizedMessage ?: "تم حظر الفحص أمنياً لمنع هجمات SSRF",
                    messageEn = e.localizedMessage ?: "Audit blocked by SSRF defense",
                    isSsrfBlocked = true
                )
            } catch (e: Exception) {
                _scanState.value = ScanState.Error(
                    messageAr = "تعذر إكمال الفحص الأمني: ${e.localizedMessage ?: "خطأ في الشبكة أو الخادم"}",
                    messageEn = "Audit failed: ${e.localizedMessage ?: "Network or server failure"}"
                )
            }
        }
    }

    fun stopScan() {
        scanJob?.cancel()
        scanJob = null
        _scanState.value = ScanState.Idle
    }

    fun runEcommerceDemo() {
        viewModelScope.launch {
            _scanState.value = ScanState.Scanning("Simulating E-Commerce Audit...", "جاري محاكاة فحص متجر إلكتروني...", 0.5f)
            kotlinx.coroutines.delay(600)
            val demoSummary = DemoScenarios.getEcommerceDemo()
            _currentSummary.value = demoSummary
            _scanState.value = ScanState.Success(demoSummary)
            _checkItems.value = SecurityAiAdvisor.generatePostFixChecklist(demoSummary.findings)
            _disclosureDraft.value = SecurityAiAdvisor.generateResponsibleDisclosure(demoSummary)
            _activeTab.value = AppTab.RESULTS
        }
    }

    fun runBankingDemo() {
        viewModelScope.launch {
            _scanState.value = ScanState.Scanning("Simulating Banking Audit...", "جاري محاكاة فحص بوابة بنك مؤمنة...", 0.5f)
            kotlinx.coroutines.delay(600)
            val demoSummary = DemoScenarios.getHardenedBankingDemo()
            _currentSummary.value = demoSummary
            _scanState.value = ScanState.Success(demoSummary)
            _checkItems.value = SecurityAiAdvisor.generatePostFixChecklist(demoSummary.findings)
            _disclosureDraft.value = SecurityAiAdvisor.generateResponsibleDisclosure(demoSummary)
            _activeTab.value = AppTab.RESULTS
        }
    }

    fun toggleCheckItem(id: String) {
        _checkItems.value = _checkItems.value.map {
            if (it.id == id) it.copy(isChecked = !it.isChecked) else it
        }
    }

    fun loadHistoricalScan(recordId: String) {
        viewModelScope.launch {
            val summary = repository.getAuditById(recordId)
            if (summary != null) {
                _currentSummary.value = summary
                _scanState.value = ScanState.Success(summary)
                _checkItems.value = SecurityAiAdvisor.generatePostFixChecklist(summary.findings)
                _disclosureDraft.value = SecurityAiAdvisor.generateResponsibleDisclosure(summary)
                _activeTab.value = AppTab.RESULTS
            }
        }
    }

    fun selectForComparison(recordId: String, isFirst: Boolean) {
        viewModelScope.launch {
            val summary = repository.getAuditById(recordId)
            if (isFirst) {
                _compareFirst.value = summary
            } else {
                _compareSecond.value = summary
            }
        }
    }

    fun deleteHistoricalScan(recordId: String) {
        viewModelScope.launch {
            repository.deleteAudit(recordId)
        }
    }
}
