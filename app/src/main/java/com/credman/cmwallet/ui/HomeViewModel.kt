package com.credman.cmwallet.ui

import android.content.Context
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.MainActivity
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.loadECPrivateKey
import com.credman.cmwallet.openid4vci.OpenId4VCI
import com.credman.cmwallet.openid4vci.data.AuthorizationDetailResponseOpenIdCredential
import com.credman.cmwallet.openid4vci.data.CredentialRequest
import com.credman.cmwallet.openid4vci.data.TokenRequest
import com.google.android.gms.identitycredentials.CreateCredentialRequest
import com.google.android.gms.identitycredentials.IdentityCredentialManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.spec.X509EncodedKeySpec

data class HomeScreenUiState(
    val credentials: List<CredentialItem>
)

class HomeViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(HomeScreenUiState(emptyList()))
    val uiState: StateFlow<HomeScreenUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            CmWalletApplication.credentialRepo.credentials.collect { credentials ->
                _uiState.update { currentState ->
                    currentState.copy(
                        credentials = credentials
                    )
                }
            }
        }
    }

    fun deleteCredential(id: String) {
        CmWalletApplication.credentialRepo.deleteCredential(id)
    }

    @OptIn(ExperimentalDigitalCredentialApi::class)
    fun testIssuance(activity: MainActivity) {
        Log.i("HomeViewModel", "testIssuance")
        val credOfferJson = JSONObject(CmWalletApplication.credentialRepo.openId4VCITestRequestJson)
        val requestJson = JSONObject().put("protocol", "openid4vci1.0").put("data", credOfferJson.toString()).toString()

        // Note: Long term this will be wrapped by a simple structured Jetpack API that
        // automatically handles the request Bundle formation and pending intent launching
        IdentityCredentialManager.getClient(activity).createCredential(
            CreateCredentialRequest(
                type = DigitalCredential.TYPE_DIGITAL_CREDENTIAL,
                credentialData = Bundle().apply { putString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON", requestJson) },
                candidateQueryData = Bundle.EMPTY,
                origin = null,
                requestJson = requestJson,
                resultReceiver = null
            )
        ).addOnSuccessListener {
            Log.d(TAG, "Issuance pending intent received ${it.pendingIntent}")
            assert(it.pendingIntent != null) { "PendingIntent must be non-null in this case" }
            activity.launchIssuanceIntent(it.pendingIntent!!)
        }.addOnFailureListener {
            Log.e(TAG, "Issuance failure", it)
        }

//        val openId4VCI = OpenId4VCI(requestJson)
//        viewModelScope.launch {
//            val tmpKey =
//                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6ef4-enmfQHRWUW40-Soj3aFB0rsEOp3tYMW-HJPBvChRANCAAT5N1NLZcub4bOgWfBwF8MHPGkfJ8Dm300cioatq9XovaLgG205FEXUOuNMEMQuLbrn8oiOC0nTnNIVn-OtSmSb"
//            val tmpPublicKey =
//                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-TdTS2XLm-GzoFnwcBfDBzxpHyfA5t9NHIqGravV6L2i4BttORRF1DrjTBDELi265_KIjgtJ05zSFZ_jrUpkmw=="
//            val privateKey =
//                loadECPrivateKey(Base64.decode(tmpKey, Base64.URL_SAFE)) as ECPrivateKey
//            val publicKeySpec = X509EncodedKeySpec(Base64.decode(tmpPublicKey, Base64.URL_SAFE))
//            val kf = KeyFactory.getInstance("EC")
//            val publicKey = kf.generatePublic(publicKeySpec)!!
//
//
//            // Figure out auth server
//            val authServer =
//                if (openId4VCI.credentialOffer.issuerMetadata.authorizationServers == null) {
//                    openId4VCI.credentialOffer.issuerMetadata.credentialIssuer
//                } else {
//                    "Can't do this yet"
//                }
//            require(openId4VCI.credentialOffer.grants != null)
//            // Check what type of grant we have
//            if (openId4VCI.credentialOffer.grants.preAuthorizedCode != null) {
//                val grant = openId4VCI.credentialOffer.grants.preAuthorizedCode
//
//                val tokenResponse = openId4VCI.requestTokenFromEndpoint(
//                    authServer, TokenRequest(
//                        grantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
//                        preAuthorizedCode = grant.preAuthorizedCode
//                    )
//                )
//                Log.i("HomeViewModel", "tokenResponse $tokenResponse")
//                tokenResponse.authorizationDetails?.forEach { authDetail ->
//                    when (authDetail) {
//                        is AuthorizationDetailResponseOpenIdCredential -> {
//                            authDetail.credentialIdentifiers.forEach { credentialId ->
//                                val credentialResponse = openId4VCI.requestCredentialFromEndpoint(
//                                    accessToken = tokenResponse.accessToken,
//                                    credentialRequest = CredentialRequest(
//                                        credentialIdentifier = credentialId,
//                                        proof = openId4VCI.createProofJwt(publicKey, privateKey)
//                                    )
//                                )
//                                Log.i("HomeViewModel", "credentialResponse $credentialResponse")
//                            }
//                        }
//                    }
//                }
//            }
//        }
    }
}