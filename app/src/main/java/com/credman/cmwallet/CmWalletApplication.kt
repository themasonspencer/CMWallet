package com.credman.cmwallet

import android.app.Application
import android.util.Log
import androidx.credentials.registry.digitalcredentials.mdoc.MdocEntry
import androidx.credentials.registry.provider.RegisterCredentialsRequest
import androidx.credentials.registry.provider.RegistryManager
import kotlinx.coroutines.launch

class CmWalletApplication : Application() {
    val registryManager = RegistryManager.create(this)
    override fun onCreate() {
        super.onCreate()

        // Register Creds
        Log.i("TAG", "ACTION_GET_CREDENTIAL ${RegistryManager.ACTION_GET_CREDENTIAL}")
        kotlinx.coroutines.MainScope().launch {
            val ret = registryManager.registerCredentials(
                request = object : RegisterCredentialsRequest("com.credman.IdentityCredential", "openid4vp2", loadTestCreds(), loadMatcher()){}
            )
            Log.i("TAG", "ret ${ret.type}")
        }
    }

    private fun loadMatcher(): ByteArray {
        val stream = assets.open("openid4vp.wasm");
        val matcher = ByteArray(stream.available())
        stream.read(matcher)
        stream.close()
        return matcher
    }

    private fun loadTestCreds(): ByteArray {
        val stream = assets.open("testcreds.json");
        val creds = ByteArray(stream.available())
        stream.read(creds)
        stream.close()
        return creds
    }

//    fun createSimpleMdocEntry() : MdocEntry {
//
//    }
}