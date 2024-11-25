package com.credman.cmwallet.openid4vci.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class Proof(
    @SerialName("proof_type") val proofType: String,
    @SerialName("jwt") val jwt: String? = null,
    @SerialName("attestation") val attestation: String? = null
)

@Serializable
data class CredentialRequest(
    @SerialName("credential_identifier") val credentialIdentifier: String? = null,
    @SerialName("credential_configuration_id") val credentialConfigurationId: String? = null,
    @SerialName("proof") val proof: Proof? = null
)

@Serializable
data class Credential(
    @SerialName("credential") val credential: String
)

@Serializable
data class CredentialResponse(
    @SerialName("credentials") val credentials: List<Credential>? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("notification_id") val notificationId: String? = null
)