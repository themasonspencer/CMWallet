package com.credman.cmwallet.openid4vci.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TokenRequest(
    @SerialName("grant_type") val grantType: String,
    @SerialName("pre-authorized_code") val preAuthorizedCode: String? = null,
    @SerialName("code") val code: String? = null,
    @SerialName("code_verifier") val codeVerifier: String? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    @SerialName("authorization_details") val authorizationDetails: String? = null,
)

@Serializable
data class TokenResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("expires_in") val expiresInSeconds: Long? = null,
    @SerialName("token_type") val tokenType: String? = null,
    @SerialName("scope") val scopes: List<String>? = null,
    @SerialName("authorization_details") val authorizationDetails: List<AuthorizationDetailResponse>? = null,
)