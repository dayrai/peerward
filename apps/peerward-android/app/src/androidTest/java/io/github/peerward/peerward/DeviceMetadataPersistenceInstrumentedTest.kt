package io.github.peerward.peerward

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.crypto.DeviceKeyUnavailable
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.UUID

/** Fault injection preserves updated preference reads but reports an unsuccessful commit. */
@RunWith(AndroidJUnit4::class)
class DeviceMetadataPersistenceInstrumentedTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val id = "commit_test_${UUID.randomUUID()}"

    @Test fun failedWriteNeverReturnsNewPublicKeysOrLeavesUsableKeys() {
        try {
            val keys = DeviceKeyStore(failedCommitContext(), forceWrapped = true)
            assertThrows(DeviceKeyUnavailable::class.java) { keys.create(id) }
            assertKeysRemoved()
        } finally {
            DeviceKeyStore(context).delete(id)
        }
    }

    @Test fun failedRemovalCommitIsReportedAfterDeletingKeys() {
        try {
            DeviceKeyStore(context, forceWrapped = true).create(id)
            assertThrows(DeviceKeyUnavailable::class.java) {
                DeviceKeyStore(failedCommitContext()).delete(id)
            }
            assertKeysRemoved()
        } finally {
            DeviceKeyStore(context).delete(id)
        }
    }

    private fun assertKeysRemoved() {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        listOf("noise", "noise-wrap", "identity-wrap", "wireguard-wrap").forEach {
            assertFalse("failed transaction left $it", store.containsAlias("peerward.$id.$it"))
        }
        assertFalse(DeviceKeyStore(context).exists(id))
    }

    private fun failedCommitContext(): Context = object : ContextWrapper(context) {
        override fun getApplicationContext(): Context = this
        override fun getSharedPreferences(name: String, mode: Int): SharedPreferences {
            val actual = context.getSharedPreferences(name, mode)
            return object : SharedPreferences by actual {
                override fun edit(): SharedPreferences.Editor {
                    val editor = actual.edit()
                    return object : SharedPreferences.Editor by editor {
                        override fun putString(key: String?, value: String?): SharedPreferences.Editor {
                            editor.putString(key, value)
                            return this
                        }
                        override fun remove(key: String?): SharedPreferences.Editor {
                            editor.remove(key)
                            return this
                        }
                        override fun commit(): Boolean {
                            editor.commit()
                            return false
                        }
                    }
                }
            }
        }
    }
}
