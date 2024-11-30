package com.credman.cmwallet.openid4vci.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class OauthAuthorizationServer(
    @SerialName("issuer") val issuer: String,
    @SerialName("authorization_endpoint") val authorizationEndpoint: String?,
    @SerialName("token_endpoint") val tokenEndpoint: String?,
    @SerialName("response_types_supported") val responseTypesSupported: List<String>?,
    @SerialName("grant_types_supported") val grantTypesSupported: List<String>?,
)

@Serializable
sealed class AuthorizationDetailResponse {
    abstract val type: String
}

@Serializable
@SerialName("openid_credential")
data class AuthorizationDetailResponseOpenIdCredential(
    @SerialName("type") override val type: String,
    @SerialName("credential_configuration_id") val credentialConfigurationId: String,
    @SerialName("credential_identifiers") val credentialIdentifiers: List<String>
) : AuthorizationDetailResponse()