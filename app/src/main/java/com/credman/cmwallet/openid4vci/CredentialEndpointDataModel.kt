package com.credman.cmwallet.openid4vci

import android.util.Log
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

internal val jsonFormat = Json { explicitNulls = false }

fun String.toCredentialResponse(): CredentialResponse? {
    return try {
        jsonFormat.decodeFromString<CredentialResponse>(this)
    } catch (e: Exception) {
        Log.e(TAG, "credential response parsing exception", e)
        null
    }
}

@Serializable
data class CredentialResponse(
    val credentials: List<Credential>? = null,
    val transaction_id: String? = null,
    val notification_id: String? = null,
)

@Serializable
data class Credential(
    // Technically this could also be an object
    val credential: String,
)

@Serializable
data class CredentialRequest(
    val credential_configuration_id: String,
    val proof: Proof? = null,
) {
    fun toJson(): String {
        return jsonFormat.encodeToString(this)
    }
}

@Serializable
class Proof(
    val proof_type: String,
    val jwt: String?,
)

internal const val JWT = "jwt"