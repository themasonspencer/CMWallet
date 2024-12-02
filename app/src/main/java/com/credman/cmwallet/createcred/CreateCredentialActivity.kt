package com.credman.cmwallet.createcred

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.credentials.CredentialProviderService
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.credentials.CreateCredentialRequest
import androidx.credentials.CreateCredentialRequest.DisplayInfo
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.ui.CredentialCard
import com.credman.cmwallet.ui.theme.CMWalletTheme

@Suppress("RestrictedApi")
class CreateCredentialActivity : ComponentActivity() {
    private val viewModel: CreateCredentialViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) {
            Log.d(TAG, "New CreateCredentialActivity")
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

            viewModel.onNewRequest(request)
        }
        setContent {
            CMWalletTheme {
                CreateCredentialScreen(viewModel)
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun CreateCredentialScreen(viewModel: CreateCredentialViewModel) {
        val uiState = viewModel.uiState
        LaunchedEffect(uiState.state) {
            handleUiResult(uiState.state)
        }

        Scaffold(
            modifier = Modifier.fillMaxSize(),
            topBar = {
                TopAppBar(
                    title = {
                        Text(text = "CMWallet")
                    }
                )
            }
        ) { innerPadding ->
            Column(
                modifier = Modifier.padding(innerPadding),
            ) {
                val credential = uiState.credentialToSave
                if (credential == null) {
                    LinearProgressIndicator(
                        Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 2.dp))
                } else {
                    Row(
                        modifier = Modifier
                            .padding(10.dp)
                            .fillMaxWidth()
                    ) {
                        Text(
                            text = "Review and add to your wallet"
                        )
                    }
                    Row(
                        modifier = Modifier
                            .padding(10.dp)
                            .fillMaxWidth()
                    ) {
                        CredentialCard(credential, {})
                    }
//                    when (val credentialDetails = credential.credential) {
//                        is MdocCredential -> CredentialClaimList(credentialDetails)
//                    }

                    Button(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        onClick = {
                            viewModel.onConfirm()
                        }
                    ) {
                        Text("Add to wallet")
                    }
                }
            }
        }
    }

    private fun handleUiResult(r: Result?) {
        when (r) {
            is Result.Error -> finishWithError(r.msg)
            is Result.Response -> finishWithResponse(r.response)
            else -> {} // No-op
        }
    }

    private fun finishWithResponse(response: CreateCredentialResponse) {
        val resultData = Intent()
        PendingIntentHandler.setCreateCredentialResponse(resultData, response)
        setResult(RESULT_OK, resultData)
        finish()
    }

    private fun finishWithError(msg: String? = null) {
        val resultData = Intent()
        PendingIntentHandler.setCreateCredentialException(
            resultData,
            CreateCredentialUnknownException(msg),
        )
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
                        request.data.apply {
                            putBundle(
                                DisplayInfo.BUNDLE_KEY_REQUEST_DISPLAY_INFO,
                                tmpRequestInto.toBundle(),
                            )
                        },
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
                "android.service.credentials.extra.CREATE_CREDENTIAL_REQUEST"
            ) ?: return null
            val requestDataBundle = requestBundle.getBundle(
                "androidx.credentials.provider.extra.CREATE_REQUEST_CREDENTIAL_DATA"
            ) ?: Bundle()
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

@Composable
fun CredentialClaimList(
//    cred: MdocCredential,
) {
//    cred.nameSpaces.forEach { namespacedData ->
//        namespacedData.value.data.forEach { field ->
//            Row(
//                modifier = Modifier.fillMaxWidth().padding(10.dp),
//                horizontalArrangement = Arrangement.SpaceBetween,
//            ) {
//                Text(field.value.display)
//                Text(field.value.displayValue ?: " " /*placeholder*/)
//            }
//        }
//    }
}