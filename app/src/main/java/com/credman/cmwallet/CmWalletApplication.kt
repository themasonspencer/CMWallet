package com.credman.cmwallet

import android.app.Application
import android.util.Log
import androidx.credentials.registry.provider.RegisterCredentialsRequest
import androidx.credentials.registry.provider.RegistryManager
import com.credman.cmwallet.data.repository.CredentialRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class CmWalletApplication : Application() {
    private val registryManager = RegistryManager.create(this)
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        val openId4VPMatcher = loadOpenId4VPMatcher()
        val testCredentialsJson = loadTestCredentials().toString(Charsets.UTF_8)

        // Add the test credentials from the included json
        CredentialRepository.addCredentialsFromJson(testCredentialsJson)

        // Listen for new credentials and update the registry.
        applicationScope.launch {
            CredentialRepository.credentialRegistryDatabase.collect { credentialDatabase ->
                Log.i("CmWalletApplication", "Credentials changed $credentialDatabase")
                registryManager.registerCredentials(
                    request = object : RegisterCredentialsRequest(
                        "com.credman.IdentityCredential",
                        "openid4vp",
                        credentialDatabase,
                        openId4VPMatcher
                    ) {}
                )
            }
        }
    }

    private fun readAsset(fileName: String): ByteArray {
        val stream = assets.open(fileName);
        val data = ByteArray(stream.available())
        stream.read(data)
        stream.close()
        return data
    }

    private fun loadOpenId4VPMatcher(): ByteArray {
        return readAsset("openid4vp.wasm");
    }

    private fun loadTestCredentials(): ByteArray {
        return readAsset("database.json");
    }
}