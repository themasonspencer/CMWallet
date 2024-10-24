package com.credman.cmwallet

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.Text
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.provider.PendingIntentHandler
import com.credman.cmwallet.ui.theme.CMWalletTheme

class GetCredentialActivity : ComponentActivity() {
    @OptIn(ExperimentalDigitalCredentialApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        if (request != null) {
            Log.i("TAG", "Request ${request.credentialOptions}")
            request.credentialOptions.forEach {
                if (it is GetDigitalCredentialOption) {
                    Log.i("TAG", "Request ${it.requestJson}")


                }
            }
        }

        enableEdgeToEdge()
        setContent {
            CMWalletTheme {
                Text("Yo")
            }
        }
    }
}