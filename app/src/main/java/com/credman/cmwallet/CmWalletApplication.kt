package com.credman.cmwallet

import android.app.Application
import android.util.Log
import androidx.credentials.registry.digitalcredentials.mdoc.MdocEntry
import androidx.credentials.registry.provider.RegisterCredentialsRequest
import androidx.credentials.registry.provider.RegistryManager
import com.credman.cmwallet.openid4vp.OpenId4VP
import kotlinx.coroutines.launch
import org.json.JSONObject

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
            //testOpenId4VP()
        }


    }

    private fun testOpenId4VP() {
        val testRequest = loadTestRequest().toString(Charsets.UTF_8)
        Log.i("TAG", "Test request $testRequest")
        val openId4VPRequest = OpenId4VP(testRequest)
        val credentialStore = JSONObject(loadTestCreds().toString(Charsets.UTF_8))
        openId4VPRequest.matchCredentials(credentialStore)
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

    private fun loadTestRequest(): ByteArray {
        val stream = assets.open("fullrequest.json");
        val matcher = ByteArray(stream.available())
        stream.read(matcher)
        stream.close()
        return matcher
    }

//    fun createSimpleMdocEntry() : MdocEntry {
//
//    }
}