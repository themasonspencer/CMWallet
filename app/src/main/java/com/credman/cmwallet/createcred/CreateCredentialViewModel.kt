package com.credman.cmwallet.createcred

import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreateCustomCredentialResponse
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.room.Credential
import com.credman.cmwallet.loadECPrivateKey
import com.credman.cmwallet.openid4vci.OpenId4VCI
import com.credman.cmwallet.openid4vci.data.CredentialRequest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.spec.X509EncodedKeySpec

sealed class Result {
    data class Error(val msg: String? = null) : Result()
    data class Response(val response: CreateCredentialResponse) : Result()
}

data class CreateCredentialUiState(
    val credentialToSave: CredentialItem? = null,
    val state: Result? = null,
)

@OptIn(ExperimentalDigitalCredentialApi::class)
class CreateCredentialViewModel : ViewModel() {
    var uiState by mutableStateOf(CreateCredentialUiState())
        private set

    private val _request = MutableStateFlow<ProviderCreateCredentialRequest?>(null)

    init {
        viewModelScope.launch {
            _request.collect {
                Log.d(TAG, "New request")
                processRequest(it)
            }
        }
    }

    fun onNewRequest(request: ProviderCreateCredentialRequest) {
        _request.value = request
    }

    suspend fun processRequest(request: ProviderCreateCredentialRequest?) {
        if (request == null) {
            uiState = CreateCredentialUiState()
            return
        }
        try {
            // This will eventually be replaced by a structured Jetpack property,
            // as opposed to having to parse a raw data from Bundle.
            val requestJsonString: String = request.callingRequest.credentialData.getString(
                "androidx.credentials.BUNDLE_KEY_REQUEST_JSON"
            )!!

            val requestJson = JSONObject(requestJsonString)
            require(requestJson.has("protocol")) { "request json missing required field protocol" }
            require(requestJson.has("data")) { "request json missing required field data" }

            Log.d(TAG, "Request json received: ${requestJson.getString("data")}")

            val openId4VCI = OpenId4VCI(requestJson.getString("data"))

            val tmpKey =
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6ef4-enmfQHRWUW40-Soj3aFB0rsEOp3tYMW-HJPBvChRANCAAT5N1NLZcub4bOgWfBwF8MHPGkfJ8Dm300cioatq9XovaLgG205FEXUOuNMEMQuLbrn8oiOC0nTnNIVn-OtSmSb"
            val tmpPublicKey =
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-TdTS2XLm-GzoFnwcBfDBzxpHyfA5t9NHIqGravV6L2i4BttORRF1DrjTBDELi265_KIjgtJ05zSFZ_jrUpkmw=="
            val privateKey =
                loadECPrivateKey(Base64.decode(tmpKey, Base64.URL_SAFE)) as ECPrivateKey
            val publicKeySpec = X509EncodedKeySpec(Base64.decode(tmpPublicKey, Base64.URL_SAFE))
            val kf = KeyFactory.getInstance("EC")
            val publicKey = kf.generatePublic(publicKeySpec)!!

            val credResponse = openId4VCI.requestCredentialFromEndpoint(
                CredentialRequest(
                    credentialConfigurationId = openId4VCI.credentialOffer.credentialConfigurationIds.first(),
                    proof = openId4VCI.createProofJwt(publicKey, privateKey)

                )
            )
            val credItem = openId4VCI.generateCredentialToSave(credResponse, privateKey)

            uiState = uiState.copy(credentialToSave = credItem)

        } catch (e: Exception) {
            Log.e(TAG, "Exception processing request", e)
            onError("Invalid request")
        }
    }

    fun onConfirm() {
        val credToSave = uiState.credentialToSave?.toJson()
        if (credToSave != null) {
            viewModelScope.launch {
                CmWalletApplication.database.credentialDao().insertAll(
                    Credential(0L, credToSave)
                )
            }
            onResponse()
        } else {
            Log.e(TAG, "Unexpected: null credential to save")
            onError("Internal error")
        }
    }

    private fun onResponse() {
        val testResponse = CreateCustomCredentialResponse(
            type = DigitalCredential.TYPE_DIGITAL_CREDENTIAL,
            data = Bundle().apply {
                putString(
                    "androidx.credentials.BUNDLE_KEY_RESPONSE_JSON",
                    "successful response"
                )
            },
        )
        uiState = uiState.copy(state = Result.Response(testResponse))
    }

    private fun onError(msg: String? = null) {
        uiState = uiState.copy(state = Result.Error(msg))
    }
}