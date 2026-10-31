package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.data.AuditDatabase
import com.example.demo.DemoScenarios
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ExampleRobolectricTest {

    @Test
    fun `read string from context`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val appName = context.getString(R.string.app_name)
        assertEquals("AI Web Security Auditor", appName)
    }

    @Test
    fun `database creation and operations`() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val db = AuditDatabase.getDatabase(context)
        assertNotNull(db)

        val demo = DemoScenarios.getEcommerceDemo()
        val dao = db.auditDao()
        assertNotNull(dao)
    }
}
