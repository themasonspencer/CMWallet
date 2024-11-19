package com.credman.cmwallet

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.registry.provider.selectedEntryId
import com.credman.cmwallet.data.model.MdocCredential
import com.credman.cmwallet.mdoc.createSessionTranscript
import com.credman.cmwallet.mdoc.filterIssuerSigned
import com.credman.cmwallet.mdoc.generateDeviceResponse
import com.credman.cmwallet.openid4vp.OpenId4VP
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedMDocClaims
import org.json.JSONObject

class GetCredentialActivity : ComponentActivity() {
    @OptIn(ExperimentalDigitalCredentialApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        if (request != null) {
            Log.i("GetCredentialActivity", "selectedEntryId ${request.selectedEntryId}")
            val selectedEntryId = JSONObject(request.selectedEntryId)
            val origin = request.callingAppInfo.getOrigin(
                CmWalletApplication.credentialRepo.privAppsJson
            ) ?: ""
            Log.i("GetCredentialActivity", "origin $origin")

            request.credentialOptions.forEach {
                if (it is GetDigitalCredentialOption) {
                    Log.i("GetCredentialActivity", "Request ${it.requestJson}")
                    val providerIdx = selectedEntryId.getInt("provider_idx")
                    val selectedId = selectedEntryId.getString("id")
                    val result = Intent()
                    try {
                        val response = processDigitalCredentialOption(
                            it.requestJson,
                            providerIdx,
                            selectedId,
                            origin
                        )

                        PendingIntentHandler.setGetCredentialResponse(
                            result, GetCredentialResponse(
                                DigitalCredential(response)
                            )
                        )

                    } catch (e: Exception) {
                        Log.e("GetCredentialActivity", "exception", e)
                        PendingIntentHandler.setGetCredentialException(
                            result,
                            GetCredentialUnknownException()
                        )
                    }
                    setResult(RESULT_OK, result)
                }
            }
        }
        finish()
    }

    private fun processDigitalCredentialOption(
        requestJson: String,
        providerIdx: Int,
        selectedID: String,
        origin: String
    ): String {
        val selectedCredential = CmWalletApplication.credentialRepo.getCredential(selectedID)
            ?: throw RuntimeException("Selected credential not found")

        val request = JSONObject(requestJson)
        require(request.has("providers")) { "DigitalCredentialOption requires providers" }
        val providers = request.getJSONArray("providers")
        require(providerIdx < providers.length()) { "Provider IDX is invalid" }
        val provider = providers.getJSONObject(providerIdx)

        require(provider.has("protocol")) { "DigitalCredentialOption provider must contain protocol" }
        require(provider.has("request")) { "DigitalCredentialOption provider must contain request" }

        val protocol = provider.getString("protocol")
        val dcRequest = provider.getString("request")

        Log.i("GetCredentialActivity", "processDigitalCredentialOption protocol $protocol")
        when (protocol) {
            "openid4vp1.0" -> {
                val openId4VPRequest = OpenId4VP(dcRequest)

                val matchedCredential =
                    openId4VPRequest.performQueryOnCredential(selectedCredential)
                Log.i("GetCredentialActivity", "matchedCredential $matchedCredential")

                // Create the response
                val vpToken = JSONObject()
                when (selectedCredential.credential) {
                    is MdocCredential -> {
                        val matchedClaims =
                            matchedCredential.matchedClaims as OpenId4VPMatchedMDocClaims
                        val filteredIssuerSigned = filterIssuerSigned(
                            selectedCredential.credential.issuerSigned,
                            matchedClaims.claims
                        )
                        val deviceResponse = generateDeviceResponse(
                            doctype = selectedCredential.credential.docType,
                            issuerSigned = filteredIssuerSigned,
                            devicePrivateKey = selectedCredential.credential.deviceKey,
                            sessionTranscript = createSessionTranscript(openId4VPRequest.getHandover(origin))
                        )
                        val encodedDeviceResponse =
                            Base64.encodeToString(deviceResponse, Base64.URL_SAFE or Base64.NO_WRAP)
                        vpToken.put(matchedCredential.dcqlId, encodedDeviceResponse)
                    }
                }

                // Create the openid4vp result
                val responseJson = JSONObject()
                responseJson.put("vp_token", vpToken)
                return responseJson.toString()

            }

            else -> throw IllegalArgumentException()
        }
    }
}

