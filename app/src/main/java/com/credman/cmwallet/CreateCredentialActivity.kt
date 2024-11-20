package com.credman.cmwallet

import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.credentials.CreateCredentialRequest
import androidx.credentials.CreateCredentialRequest.DisplayInfo
import android.service.credentials.CredentialProviderService
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.credentials.CreateCustomCredentialResponse
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.registry.provider.selectedEntryId
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import org.json.JSONObject

@OptIn(ExperimentalDigitalCredentialApi::class)
class CreateCredentialActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val request = toRequest(intent)
        if (request == null) {
            Log.e(TAG, "[CreateCredentialActivity] Got empty request!")
            finish()
            return
        }

        val origin = request.callingAppInfo.getOrigin(
            CmWalletApplication.credentialRepo.privAppsJson
        ) ?: ""
        Log.i(TAG, "[CreateCredentialActivity] origin $origin")

        val testResponse = CreateCustomCredentialResponse(
            type = DigitalCredential.TYPE_DIGITAL_CREDENTIAL,
            data = Bundle().apply {
                putString("androidx.credentials.BUNDLE_KEY_RESPONSE_JSON", "test response")
            },
        )

        val resultData = Intent()
        PendingIntentHandler.setCreateCredentialResponse(resultData, testResponse)
        setResult(RESULT_OK, resultData)
        finish()
    }

    /**
     * Eventually this should be replaced as a single call
     * val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
     */
    fun toRequest(intent: Intent): ProviderCreateCredentialRequest? {
        val tmpRequestInto = DisplayInfo("userId")
        if (Build.VERSION.SDK_INT >= 34) {
            val request = intent.getParcelableExtra(
                CredentialProviderService.EXTRA_CREATE_CREDENTIAL_REQUEST,
                android.service.credentials.CreateCredentialRequest::class.java
            ) ?: return null
            return try {
                ProviderCreateCredentialRequest(
                    callingRequest =
                    CreateCredentialRequest.createFrom(
                        request.type,
                        request.data.apply { putBundle(
                            DisplayInfo.BUNDLE_KEY_REQUEST_DISPLAY_INFO,
                            tmpRequestInto.toBundle(),
                        ) },
                        request.data,
                        requireSystemProvider = false,
                        request.callingAppInfo.origin
                    ),
                    callingAppInfo =
                    CallingAppInfo.create(
                        request.callingAppInfo.packageName,
                        request.callingAppInfo.signingInfo,
                        request.callingAppInfo.origin
                    ),
                    biometricPromptResult = null
                )
            } catch (e: IllegalArgumentException) {
                return null
            }
        } else {
            val requestBundle = intent.getBundleExtra(
                "android.service.credentials.extra.CREATE_CREDENTIAL_REQUEST") ?: return null
            val requestDataBundle = requestBundle.getBundle(
                "androidx.credentials.provider.extra.CREATE_REQUEST_CREDENTIAL_DATA") ?: Bundle()
            requestDataBundle.putBundle(
                DisplayInfo.BUNDLE_KEY_REQUEST_DISPLAY_INFO,
                tmpRequestInto.toBundle(),
            )
            requestBundle.putBundle(
                "androidx.credentials.provider.extra.CREATE_REQUEST_CREDENTIAL_DATA",
                requestDataBundle
            )
            return try {
                ProviderCreateCredentialRequest.fromBundle(requestBundle)
            } catch (e: Exception) {
                Log.e(TAG, "Parsing error", e)
                null
            }
        }
    }
}