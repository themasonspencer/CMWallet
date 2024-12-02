package com.credman.cmwallet.getcred

import android.content.Context
import android.content.Intent
import android.os.Bundle
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
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.data.model.CredentialKeySoftware
import com.credman.cmwallet.decodeBase64UrlNoPadding
import com.credman.cmwallet.loadECPrivateKey
import com.credman.cmwallet.mdoc.createSessionTranscript
import com.credman.cmwallet.mdoc.filterIssuerSigned
import com.credman.cmwallet.mdoc.generateDeviceResponse
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationMDoc
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationUnknownFormat
import com.credman.cmwallet.openid4vp.OpenId4VP
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedMDocClaims
import com.credman.cmwallet.toBase64UrlNoPadding
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
            var origin = request.callingAppInfo.getOrigin(
                CmWalletApplication.credentialRepo.privAppsJson
            ) ?: ""
            Log.i("GetCredentialActivity", "origin $origin")
            if (origin.endsWith(":443")) {
                origin = origin.substringBefore(":443")
                Log.i("GetCredentialActivity", "new origin $origin")
            }

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
                                .setStrongOrDeviceAuthenticators(this@GetCredentialActivity)
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
                when (selectedCredential.config) {
                    is CredentialConfigurationMDoc -> {
                        val matchedClaims =
                            matchedCredential.matchedClaims as OpenId4VPMatchedMDocClaims
                        val filteredIssuerSigned = filterIssuerSigned(
                            selectedCredential.credentials.first().credential.decodeBase64UrlNoPadding(),
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
                        val devicePrivateKey =
                            loadECPrivateKey((selectedCredential.credentials.first().key as CredentialKeySoftware).privateKey.decodeBase64UrlNoPadding())
                        val deviceResponse = generateDeviceResponse(
                            doctype = selectedCredential.config.doctype,
                            issuerSigned = filteredIssuerSigned,
                            devicePrivateKey = devicePrivateKey,
                            sessionTranscript = createSessionTranscript(
                                openId4VPRequest.getHandover(
                                    origin
                                )
                            ),
                            deviceNamespaces = deviceNamespaces

                        )
                        val encodedDeviceResponse = deviceResponse.toBase64UrlNoPadding()
                        vpToken.put(matchedCredential.dcqlId, encodedDeviceResponse)
                    }

                    is CredentialConfigurationUnknownFormat -> TODO()
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

/**
 * Returns biometric Strong only if it is available. Otherwise, also allows device credentials.
 */
fun BiometricPrompt.PromptInfo.Builder.setStrongOrDeviceAuthenticators(context: Context): BiometricPrompt.PromptInfo.Builder {
    val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
    val biometricManager = BiometricManager.from(context)
    if (biometricManager.canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS) {
        this.setAllowedAuthenticators(authenticators).setNegativeButtonText("Cancel")
    } else {
        this.setAllowedAuthenticators(
            authenticators or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
    }
    return this
}

