package com.credman.cmwallet

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.registry.provider.selectedEntryId
import androidx.fragment.app.FragmentActivity
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.data.model.MdocCredential
import com.credman.cmwallet.mdoc.createSessionTranscript
import com.credman.cmwallet.mdoc.filterIssuerSigned
import com.credman.cmwallet.mdoc.generateDeviceResponse
import com.credman.cmwallet.openid4vp.OpenId4VP
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedMDocClaims
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.json.JSONObject

class GetCredentialActivity : FragmentActivity() {
    @OptIn(ExperimentalDigitalCredentialApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        var shouldFinishActivity = true
        if (request != null) {
            Log.i(TAG, "selectedEntryId ${request.selectedEntryId}")
            val selectedEntryId = JSONObject(request.selectedEntryId)
            val origin = request.callingAppInfo.getOrigin(
                CmWalletApplication.credentialRepo.privAppsJson
            ) ?: ""
            Log.i("GetCredentialActivity", "origin $origin")

            request.credentialOptions.forEach {
                if (it is GetDigitalCredentialOption) {
                    Log.i(TAG, "Request ${it.requestJson}")
                    val providerIdx = selectedEntryId.getInt("provider_idx")
                    val selectedId = selectedEntryId.getString("id")
                    val resultData = Intent()
                    shouldFinishActivity = false
                    try {
                        val response = processDigitalCredentialOption(
                            it.requestJson,
                            providerIdx,
                            selectedId,
                            origin
                        )

                        val biometricPrompt = BiometricPrompt(
                            this@GetCredentialActivity,
                            object : BiometricPrompt.AuthenticationCallback() {
                                override fun onAuthenticationFailed() {
                                    super.onAuthenticationFailed()
                                    Log.d(TAG, "onAuthenticationFailed")
                                }

                                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                    Log.d(TAG, "onAuthenticationSucceeded")

                                    PendingIntentHandler.setGetCredentialResponse(
                                        resultData, GetCredentialResponse(
                                            DigitalCredential(response.responseJson)
                                        )
                                    )

                                    setResult(RESULT_OK, resultData)
                                    finish()
                                }

                                override fun onAuthenticationError(
                                    errorCode: Int,
                                    errString: CharSequence
                                ) {
                                    Log.e(TAG, "onAuthenticationError $errorCode $errString")
                                    PendingIntentHandler.setGetCredentialException(
                                        resultData,
                                        GetCredentialUnknownException()
                                    )
                                    setResult(RESULT_OK, resultData)
                                    finish()
                                }
                            })
                        Log.d(TAG, "authenticating")
                        biometricPrompt.authenticate(
                            BiometricPrompt.PromptInfo.Builder()
                                .setTitle(response.authenticationTitle)
                                .setSubtitle(response.authenticationSubtitle)
                                .setConfirmationRequired(false)
                                .setAllowedAuthenticators(
                                    BiometricManager.Authenticators.BIOMETRIC_STRONG
//                                            or BiometricManager.Authenticators.DEVICE_CREDENTIAL
                                )
                                .setNegativeButtonText("Cancel")
                                .build()
                        )

                    } catch (e: Exception) {
                        Log.e(TAG, "exception", e)
                        PendingIntentHandler.setGetCredentialException(
                            resultData,
                            GetCredentialUnknownException()
                        )
                        setResult(RESULT_OK, resultData)
                        finish()
                    }
                }
            }
        }
        if (shouldFinishActivity) {
            finish()
        }
    }

    private data class DigitalCredentialResult(
        val responseJson: String,
        val authenticationTitle: CharSequence,
        val authenticationSubtitle: CharSequence?
    )

    @Serializable
    data class DigitalCredentialRequestOptions(
        val providers: List<DigitalCredentialRequest>
    )

    @Serializable
    data class DigitalCredentialRequest(
        val protocol: String,
        val request: String
    )

    private fun processDigitalCredentialOption(
        requestJson: String,
        providerIdx: Int,
        selectedID: String,
        origin: String
    ): DigitalCredentialResult {
        val selectedCredential = CmWalletApplication.credentialRepo.getCredential(selectedID)
            ?: throw RuntimeException("Selected credential not found")
        var authenticationTitle: CharSequence = "Verify your identity"
        var authenticationSubtitle: CharSequence? = null

        val digitalCredentialRequestOptions =
            Json.decodeFromString<DigitalCredentialRequestOptions>(requestJson)
        Log.i(
            "GetCredentialActivity",
            "digitalCredentialRequestOptions $digitalCredentialRequestOptions"
        )

        val provider = digitalCredentialRequestOptions.providers[providerIdx]

        Log.i(
            "GetCredentialActivity",
            "processDigitalCredentialOption protocol ${provider.protocol}"
        )
        when (provider.protocol) {
            "openid4vp1.0" -> {
                val openId4VPRequest = OpenId4VP(provider.request)
                Log.i("GetCredentialActivity", "nonce ${openId4VPRequest.nonce}")
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
                        val deviceNamespaces = if (openId4VPRequest.transactionData.isEmpty()) {
                            emptyMap<String, Any>()
                        } else {
                            val deviceSignedTransactionData =
                                openId4VPRequest.generateDeviceSignedTransactionData(
                                    matchedCredential.dcqlId
                                )
                            if (deviceSignedTransactionData.authenticationTitleAndSubtitle != null) {
                                authenticationTitle =
                                    deviceSignedTransactionData.authenticationTitleAndSubtitle.first
                                authenticationSubtitle =
                                    deviceSignedTransactionData.authenticationTitleAndSubtitle.second
                            }
                            mapOf(
                                Pair(
                                    "net.openid.open4vc",
                                    deviceSignedTransactionData.deviceSignedTransactionData
                                )
                            )
                        }
                        val deviceResponse = generateDeviceResponse(
                            doctype = selectedCredential.credential.docType,
                            issuerSigned = filteredIssuerSigned,
                            devicePrivateKey = selectedCredential.credential.deviceKey,
                            sessionTranscript = createSessionTranscript(
                                openId4VPRequest.getHandover(
                                    origin
                                )
                            ),
                            deviceNamespaces = deviceNamespaces

                        )
                        val encodedDeviceResponse =
                            Base64.encodeToString(deviceResponse, Base64.URL_SAFE or Base64.NO_WRAP)
                        vpToken.put(matchedCredential.dcqlId, encodedDeviceResponse)
                    }
                }

                // Create the openid4vp result
                val responseJson = JSONObject()
                responseJson.put("vp_token", vpToken)
                return DigitalCredentialResult(
                    responseJson = responseJson.toString(),
                    authenticationTitle = authenticationTitle,
                    authenticationSubtitle = authenticationSubtitle,
                )

            }

            else -> throw IllegalArgumentException()
        }
    }
}

