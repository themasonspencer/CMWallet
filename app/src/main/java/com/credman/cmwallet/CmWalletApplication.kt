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
            registryManager.registerCredentials(
                request = object : RegisterCredentialsRequest("com.credman.IdentityCredential", "openid4vp", byteArrayOf(), loadMatcher()){}
            )
        }
    }

    private fun loadMatcher(): ByteArray {
        val stream = assets.open("matcher.wasm");
        val matcher = ByteArray(stream.available())
        stream.read(matcher)
        stream.close()
        return matcher
    }

//    fun createSimpleMdocEntry() : MdocEntry {
//
//    }
}