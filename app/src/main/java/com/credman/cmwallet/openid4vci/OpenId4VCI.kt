package com.credman.cmwallet.openid4vci

import android.util.Base64
import android.util.Log
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.data.room.Credential
import com.credman.cmwallet.loadECPrivateKey
import com.credman.cmwallet.mdoc.toCredentialItem
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.http.headers
import org.json.JSONObject
import java.security.PrivateKey

class OpenId4VCI(val request: String) {
    val requestJson: JSONObject = JSONObject(request)

    val credentialIssuer: String
    val credentialConfigurationIds: List<String>

    // Credential Issuer Metadata Parameters
    val credentialEndpoint: String
    val credentialConfigurationsSupportedMap: Map<String, CredConfigsSupportedItem>

    private lateinit var deviceKey: PrivateKey

    init {
        require(requestJson.has(CREDENTIAL_ISSUER)) { "Issuance request must contain $CREDENTIAL_ISSUER" }
        require(requestJson.has(CREDENTIAL_CONFIGURATION_IDS)) { "Issuance request must contain $CREDENTIAL_CONFIGURATION_IDS" }
        // This should be required for the DC API browser profile
        require(requestJson.has(ISSUER_METADATA)) { "Issuance request must contain $ISSUER_METADATA" }

        credentialIssuer = requestJson.getString(CREDENTIAL_ISSUER)
        credentialConfigurationIds = requestJson.getJSONArray(CREDENTIAL_CONFIGURATION_IDS).let {
            val ids = mutableListOf<String>()
            for (i in 0..<it.length()) {
                ids.add(it.getString(i))
            }
            ids
        }
        require(credentialConfigurationIds.isNotEmpty()) { "Credential configuration id list shouldn't be empty" }

        val issuerMetadataJson = requestJson.getJSONObject(ISSUER_METADATA)
        require(issuerMetadataJson.has(CREDENTIAL_ENDPOINT)) { "Issuance request must contain $CREDENTIAL_ENDPOINT" }
        credentialEndpoint = issuerMetadataJson.getString(CREDENTIAL_ENDPOINT)
        require(issuerMetadataJson.has(CREDENTIAL_CONFIGURATION_SUPPORTED)) { "Issuance request must contain $CREDENTIAL_CONFIGURATION_SUPPORTED" }
        val credConfigSupportedJson = issuerMetadataJson.getJSONObject(CREDENTIAL_CONFIGURATION_SUPPORTED)
        val itr = credConfigSupportedJson.keys()
        val tmpMap = mutableMapOf<String, CredConfigsSupportedItem>()
        while (itr.hasNext()) {
            val configId = itr.next()
            val item = credConfigSupportedJson.getJSONObject(configId)
            tmpMap[configId] = CredConfigsSupportedItem.createFrom(credConfigSupportedJson.getJSONObject(configId))
        }
        credentialConfigurationsSupportedMap = tmpMap
    }

    suspend fun requestAndSaveCredential() {
        val client = HttpClient(CIO)
        Log.d(TAG, "Requesting to credential endpoint $credentialEndpoint")
        val credConfigId = credentialConfigurationIds.first()
        val httpResponse = client.post(credentialEndpoint) {
            headers {
                append(HttpHeaders.Authorization, getAuthToken())
            }
            contentType(ContentType.Application.Json)
            setBody(
                CredentialRequest(
                    credConfigId,
                    proof = Proof(
                        JWT,
                        jwt = generateDeviceKeyJwt()
                    )
                ).toJson()
            )
        }

        if (httpResponse.status.value == 202) {
            Log.d(TAG, "Successful credential endpoint response." +
                    " Content type: ${httpResponse.headers[HttpHeaders.ContentType]}.")
            val stringBody: String = httpResponse.body()
            Log.d(TAG, "Response body: $stringBody")
            val credResponse = stringBody.toCredentialResponse()
            val credentialIssuerSigned = Base64.decode(
                credResponse!!.credentials!!.first().credential,
                Base64.URL_SAFE
            )
            val credItem = toCredentialItem(
                credentialIssuerSigned,
                deviceKey,
                credentialConfigurationsSupportedMap[credConfigId]!!)
            CmWalletApplication.database.credentialDao().insertAll(Credential(0L, credItem.toJson()))
        } else {
            Log.e(TAG, "Error credential endpoint code: ${httpResponse.status.value}")
            TODO()
        }
    }

    private fun generateDeviceKeyJwt(): String {
        // TODO: generate real device key
        val tmpKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6ef4-enmfQHRWUW40-Soj3aFB0rsEOp3tYMW-HJPBvChRANCAAT5N1NLZcub4bOgWfBwF8MHPGkfJ8Dm300cioatq9XovaLgG205FEXUOuNMEMQuLbrn8oiOC0nTnNIVn-OtSmSb"
        deviceKey = loadECPrivateKey(Base64.decode(tmpKey, Base64.URL_SAFE))
        return "TODO"
    }

    private fun getAuthToken(): String {
        return "TODO"
    }
}