package com.credman.cmwallet.openid4vci.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class NonceResponse(
    @SerialName("c_nonce") val cNonce: String,
    @SerialName("c_nonce_expires_in") val cNonceExpiresIn: Int? = null
)