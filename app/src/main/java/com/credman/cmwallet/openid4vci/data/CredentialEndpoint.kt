package com.credman.cmwallet.openid4vci.data

import kotlinx.serialization.Serializable

@Serializable
data class Proof(
    val proof_type: String,
    val jwt: String? = null,
    val attestation: String? = null
)

@Serializable
data class CredentialRequest(
    val credential_identifier: String? = null,
    val credential_configuration_id: String? = null,
    val proof: Proof? = null
)

@Serializable
data class Credential(
    val credential: String
)

@Serializable
data class CredentialResponse(
    val credentials: List<Credential>? = null,
    val transaction_id: String? = null,
    val notification_id: String? = null
)