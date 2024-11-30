package com.credman.cmwallet.data.model

import com.credman.cmwallet.openid4vci.data.CredentialConfiguration
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialItem(
    val id: String,
    val config: CredentialConfiguration,
    val displayData: CredentialDisplayData,
    val credentials: List<Credential>
)

@Serializable
data class Credential(
    val key: CredentialKey,
    val credential: String
)

@Serializable
sealed class CredentialKey {
    enum class KeyType(val type: String) {
        SOFTWARE("SOFTWARE"),
        HARDWARE("HARDWARE")
    }

    abstract val type: KeyType
}

@Serializable
@SerialName("SOFTWARE")
data class CredentialKeySoftware(
    override val type: KeyType = KeyType.SOFTWARE,
    val publicKey: String,
    val privateKey: String
) : CredentialKey()

@Serializable
@SerialName("HARDWARE")
data class CredentialKeyHardware(
    override val type: KeyType = KeyType.HARDWARE,
    val publicKey: String,
    val privateKey: String
) : CredentialKey()

@Serializable
data class CredentialDisplayData(
    val title: String,
    val subtitle: String?,
    val icon: String?
)
