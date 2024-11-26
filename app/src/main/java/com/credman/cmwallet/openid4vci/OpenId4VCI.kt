package com.credman.cmwallet.openid4vci

import android.util.Base64
import android.util.Log
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.createJWTES256
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.mdoc.toCredentialItem
import com.credman.cmwallet.openid4vci.data.CredentialRequest
import com.credman.cmwallet.openid4vci.data.CredentialResponse
import com.credman.cmwallet.openid4vci.data.NonceResponse
import com.credman.cmwallet.openid4vci.data.Proof
import com.credman.cmwallet.toJWK
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.json.JSONObject
import java.security.PrivateKey
import java.security.PublicKey
import java.time.Instant


class OpenId4VCI(val credentialOfferJson: String) {
    val credentialOffer = JSONObject(credentialOfferJson)

    val credentialIssuer: String
    val credentialConfigurationIds: List<String>

    // Credential Issuer Metadata Parameters
    val credentialEndpoint: String
    val nonceEndpoint: String?
    val credentialConfigurationsSupportedMap: Map<String, CredConfigsSupportedItem>

    private val httpClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json()
        }
    }

    init {
        require(credentialOffer.has(CREDENTIAL_ISSUER)) { "Issuance request must contain $CREDENTIAL_ISSUER" }
        require(credentialOffer.has(CREDENTIAL_CONFIGURATION_IDS)) { "Issuance request must contain $CREDENTIAL_CONFIGURATION_IDS" }
        // This should be required for the DC API browser profile
        require(credentialOffer.has(ISSUER_METADATA)) { "Issuance request must contain $ISSUER_METADATA" }

        credentialIssuer = credentialOffer.getString(CREDENTIAL_ISSUER)
        credentialConfigurationIds =
            credentialOffer.getJSONArray(CREDENTIAL_CONFIGURATION_IDS).let {
                val ids = mutableListOf<String>()
                for (i in 0..<it.length()) {
                    ids.add(it.getString(i))
                }
                ids
            }
        require(credentialConfigurationIds.isNotEmpty()) { "Credential configuration id list shouldn't be empty" }

        val issuerMetadataJson = credentialOffer.getJSONObject(ISSUER_METADATA)
        require(issuerMetadataJson.has(CREDENTIAL_ENDPOINT)) { "Issuance request must contain $CREDENTIAL_ENDPOINT" }
        credentialEndpoint = issuerMetadataJson.getString(CREDENTIAL_ENDPOINT)
        nonceEndpoint = issuerMetadataJson.optString(NONCE_ENDPOINT)

        require(issuerMetadataJson.has(CREDENTIAL_CONFIGURATION_SUPPORTED)) { "Issuance request must contain $CREDENTIAL_CONFIGURATION_SUPPORTED" }
        val credConfigSupportedJson =
            issuerMetadataJson.getJSONObject(CREDENTIAL_CONFIGURATION_SUPPORTED)
        val itr = credConfigSupportedJson.keys()
        val tmpMap = mutableMapOf<String, CredConfigsSupportedItem>()
        while (itr.hasNext()) {
            val configId = itr.next()
            val item = credConfigSupportedJson.getJSONObject(configId)
            tmpMap[configId] =
                CredConfigsSupportedItem.createFrom(credConfigSupportedJson.getJSONObject(configId))
        }
        credentialConfigurationsSupportedMap = tmpMap
    }

    suspend fun requestNonceFromEndpoint(): NonceResponse {
        require(nonceEndpoint != null) { "nonce_endpoint must be set when requesting a nonce" }
        return httpClient.post(nonceEndpoint).body()
    }

    suspend fun requestCredentialFromEndpoint(
        credentialRequest: CredentialRequest
    ): CredentialResponse {
        Log.d(
            TAG,
            "Requesting to credential endpoint $credentialEndpoint ${
                Json.encodeToString(credentialRequest)
            }"
        )
        val httpResponse = HttpClient(CIO).post(credentialEndpoint) {
            bearerAuth("fdfd")
            contentType(ContentType.Application.Json)
            setBody(
                Json.encodeToString(credentialRequest)
            )
        }

        if (httpResponse.status == HttpStatusCode.OK) {
            Log.d(
                TAG, "Successful credential endpoint response." +
                        " Content type: ${httpResponse.headers[HttpHeaders.ContentType]}."
            )
            val responseJson: String = httpResponse.body()
            Log.d(TAG, "Response body: $responseJson")
            return Json.decodeFromString(responseJson)
        } else {
            throw RuntimeException("Credential Endpoint error: ${httpResponse.status}")
        }
    }

    suspend fun createJwt(publicKey: PublicKey, privateKey: PrivateKey): String {
        val nonceResponse = requestNonceFromEndpoint()
        return createJWTES256(
            header = buildJsonObject {
                put("typ", "openid4vci-proof+jwt")
                put("alg", "ES256")
                put("jwk", publicKey.toJWK())
            },
            payload = buildJsonObject {
                put("aud", credentialIssuer)
                put("iat", Instant.now().epochSecond)
                put("nonce", nonceResponse.cNonce)
            },
            privateKey = privateKey
        )
    }

    suspend fun createProofJwt(publicKey: PublicKey, privateKey: PrivateKey): Proof {
        return Proof(
            proofType = "jwt",
            jwt = createJwt(publicKey, privateKey)
        )
    }

    fun generateCredentialToSave(
        credentialEndpointResponse: CredentialResponse,
        deviceKey: PrivateKey,
        credentialConfigurationId: String = credentialConfigurationIds.first(),
    ): CredentialItem {
        val credentialIssuerSigned = Base64.decode(
            credentialEndpointResponse.credentials!!.first().credential,
            Base64.URL_SAFE
        )
        return toCredentialItem(
            credentialIssuerSigned,
            deviceKey,
            credentialConfigurationsSupportedMap[credentialConfigurationId]!!
        )
    }
}