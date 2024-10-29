package com.credman.cmwallet

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.Text
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.registry.provider.selectedEntryId
import com.credman.cmwallet.ui.theme.CMWalletTheme
import org.json.JSONObject

class GetCredentialActivity : ComponentActivity() {
    @OptIn(ExperimentalDigitalCredentialApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        if (request != null) {
            Log.i("TAG", "selectedEntryId ${request.selectedEntryId}")

            request.credentialOptions.forEach {
                if (it is GetDigitalCredentialOption) {
                    Log.i("TAG", "Request ${it.requestJson}")



                    val result = Intent()
                    PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(
                        DigitalCredential("{}")
                    ))
                    setResult(RESULT_OK, result)
                }
            }
        }

        finish()
    }
}