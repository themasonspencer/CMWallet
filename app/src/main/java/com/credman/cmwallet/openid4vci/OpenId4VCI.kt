package com.credman.cmwallet.openid4vci

import android.util.Base64
import android.util.Log
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.createJWTES256
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.mdoc.toCredentialItem
import com.credman.cmwallet.openid4vci.data.CredentialOffer
import com.credman.cmwallet.openid4vci.data.CredentialRequest
import com.credman.cmwallet.openid4vci.data.CredentialResponse
import com.credman.cmwallet.openid4vci.data.NonceResponse
import com.credman.cmwallet.openid4vci.data.OauthAuthorizationServer
import com.credman.cmwallet.openid4vci.data.Proof
import com.credman.cmwallet.openid4vci.data.TokenRequest
import com.credman.cmwallet.openid4vci.data.TokenResponse
import com.credman.cmwallet.toJWK
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.append
import io.ktor.http.contentType
import io.ktor.http.parameters
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.security.PrivateKey
import java.security.PublicKey
import java.time.Instant

class OpenId4VCI(val credentialOfferJson: String) {
    private val json = Json {
        explicitNulls = false
        ignoreUnknownKeys = true
    }
    val credentialOffer: CredentialOffer = json.decodeFromString(credentialOfferJson)
    private val authServerCache = mutableMapOf<String, OauthAuthorizationServer>()
    private val httpClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json()
        }
    }

    suspend fun requestAuthServerMetadata(server: String): OauthAuthorizationServer {
        if (server !in authServerCache) {
            authServerCache[server] = httpClient.get("$server/.well-known/oauth-authorization-server").body()
        }
        return authServerCache[server]!!
    }

    suspend fun requestNonceFromEndpoint(): NonceResponse {
        require(credentialOffer.issuerMetadata.nonceEndpoint != null) { "nonce_endpoint must be set when requesting a nonce" }
        return httpClient.post(credentialOffer.issuerMetadata.nonceEndpoint).body()
    }

    suspend fun requestTokenFromEndpoint(
        authServer: String,
        tokenRequest: TokenRequest
    ): TokenResponse {
        val endpoint = requestAuthServerMetadata(authServer).tokenEndpoint
        require(endpoint != null) {"Token Endpoint Missed from Auth Server metadata"}
        return httpClient.submitForm(
            url = endpoint,
            formParameters = parameters {
                json.encodeToJsonElement(tokenRequest).jsonObject.forEach {key, element ->
                    append(key, element.jsonPrimitive.content)
                }
            }
        ) {

        }.body()
    }

    suspend fun requestCredentialFromEndpoint(
        accessToken: String,
        credentialRequest: CredentialRequest
    ): CredentialResponse {
        return httpClient.post(credentialOffer.issuerMetadata.credentialEndpoint) {
            bearerAuth(accessToken)
            contentType(ContentType.Application.Json)
            setBody(credentialRequest)
        }.body()
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
                put("aud", credentialOffer.credentialIssuer)
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
        credentialConfigurationId: String = credentialOffer.credentialConfigurationIds.first(),
    ): CredentialItem {
        val credentialIssuerSigned = Base64.decode(
            credentialEndpointResponse.credentials!!.first().credential,
            Base64.URL_SAFE
        )
        return toCredentialItem(
            credentialIssuerSigned,
            deviceKey,
            credentialOffer.issuerMetadata.credentialConfigurationsSupported[credentialConfigurationId]!!
        )
    }
}