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
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.registry.provider.selectedEntryId
import com.credman.cmwallet.openid4vp.OpenId4VP
import com.credman.cmwallet.ui.theme.CMWalletTheme
import org.json.JSONObject
import java.lang.Exception

class GetCredentialActivity : ComponentActivity() {
    @OptIn(ExperimentalDigitalCredentialApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        if (request != null) {
            Log.i("GetCredentialActivity", "selectedEntryId ${request.selectedEntryId}")
            val selectedEntryId = JSONObject(request.selectedEntryId)

            request.credentialOptions.forEach {
                if (it is GetDigitalCredentialOption) {
                    Log.i("GetCredentialActivity", "Request ${it.requestJson}")
                    val providerIdx = selectedEntryId.getInt("provider_idx")
                    val selectedId = selectedEntryId.getString("id")
                    val result = Intent()
                    try {
                        val response =
                            processDigitalCredentialOption(it.requestJson, providerIdx, selectedId)
                        PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(
                            DigitalCredential(response)
                        ))

                    } catch(_: Exception) {
                        PendingIntentHandler.setGetCredentialException(result, GetCredentialUnknownException())
                    }
                    setResult(RESULT_OK, result)
                }
            }
        }
        finish()
    }

    fun processDigitalCredentialOption(requestJson: String, providerIdx: Int, selectedID: String): String {
        val request = JSONObject(requestJson)
        require(request.has("providers")) {"DigitalCredentialOption requires providers"}
        val providers = request.getJSONArray("providers")
        require(providerIdx < providers.length()) {"Provider IDX is invalid"}
        val provider = providers.getJSONObject(providerIdx)

        require(provider.has("protocol")) {"DigitalCredentialOption provider must contain protocol"}
        require(provider.has("request")) {"DigitalCredentialOption provider must contain request"}

        val protocol = provider.getString("protocol")
        val dcRequest = provider.getString("request")

        when (protocol) {
            "openid4vp1.0" -> {
                val openId4VPRequest = OpenId4VP(dcRequest)
                val credentialStore = JSONObject(loadTestCreds().toString(Charsets.UTF_8))
                val matchedDocuments = openId4VPRequest.matchCredentials(credentialStore)
                Log.i("GetCredentialActivity", "matchedDocuments $matchedDocuments")

                // We only support one matched document today
                val dcqlCredentialId = matchedDocuments.keys.iterator().next()
                val matchedCredentials = matchedDocuments.get(dcqlCredentialId)!!
                val matchedCredentialsFiltered = matchedCredentials.filter {it.id == selectedID}
                require(matchedCredentialsFiltered.size == 1) {"matchedCredentialsFiltered isn't 1"}
                val matchedCredential = matchedCredentialsFiltered[0]
                Log.i("GetCredentialActivity", "matchedCredential $matchedCredential")

                // Get the credential
                val vpToken = JSONObject()
                vpToken.put(dcqlCredentialId, "XXXXXX")
                // Create the openid4vp result
                val responseJson = JSONObject()
                responseJson.put("vp_token", vpToken)
                return responseJson.toString()

            }
            else -> throw IllegalArgumentException()
        }
    }

    private fun loadTestCreds(): ByteArray {
        val stream = assets.open("testcreds.json");
        val creds = ByteArray(stream.available())
        stream.read(creds)
        stream.close()
        return creds
    }
}

