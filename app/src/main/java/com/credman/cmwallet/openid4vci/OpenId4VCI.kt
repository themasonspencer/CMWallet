package com.credman.cmwallet.openid4vci

import android.util.Log
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
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

class OpenId4VCI(val request: String) {
    val requestJson: JSONObject = JSONObject(request)

    val credentialIssuer: String
    val credentialConfigurationIds: List<String>

    // Credential Issuer Metadata Parameters
    val credentialEndpoint: String
    val credentialConfigurationsSupportedMap: Map<String, CredConfigsSupportedItem>

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

    suspend fun requestCredential() {
        val client = HttpClient(CIO)
        val httpResponse = client.post(credentialEndpoint) {
            headers {
                append(HttpHeaders.Authorization, getAuthToken())
            }
            contentType(ContentType.Application.Json)
            setBody(
                CredentialRequest(
                    credentialConfigurationIds.first(),
                    proof = Proof(
                        JWT,
                        jwt = generateDeviceKeyJwt()
                    )
                ).toJson()
            )
        }

        if (httpResponse.status.value == 202) {
            Log.d(TAG, "Successful credential endpoint response." +
                    "Content type: ${httpResponse.headers[HttpHeaders.ContentType]}, " +
                    "Content body: ${httpResponse.body<String>()}")
            val credResponse = httpResponse.body<String>().toCredentialResponse()
            // TODO: remove !!
            val credential = credResponse!!.credentials!!.first().credential
            TODO()
        } else {
            Log.e(TAG, "Error credential endpoint code: ${httpResponse.status.value}")
            TODO()
        }
    }

    private fun generateDeviceKeyJwt(): String {
        return "TODO"
    }

    private fun getAuthToken(): String {
        return "TODO"
    }
}