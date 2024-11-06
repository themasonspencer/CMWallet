package com.credman.cmwallet.data.model

import android.graphics.Bitmap
import org.json.JSONObject

class CredentialItem(
    val id: String,
    val credential: Credential,
    val metadata: CredentialMetadata, // Temporary Assumption: 1 and only 1 metadata per credential
) {
    constructor(id: String, json: JSONObject) : this(
        id = id,
        credential = Credential.fromJson(json),
        metadata = json.getJSONObject(METADATA).let {
            val metadataKey = it.keys().next()
            CredentialMetadata.fromJson(metadataKey, it.getJSONObject(metadataKey))
        }
    )

}

sealed class Credential(
    val format: String
) {
    companion object {
        fun fromJson(json: JSONObject): Credential = when (json.getString(FORMAT)) {
            MSO_MDOC -> MdocCredential(json.getJSONObject(CREDENTIAL))
            else -> throw IllegalArgumentException("Credential format ${json.getString(FORMAT)} is not supported")
        }
    }
}

data class MdocCredential(
    val docType: String,
    val nameSpaces: Map<String, MdocNameSpace>,
) : Credential(format = MSO_MDOC) {
    constructor(json: JSONObject): this(
        docType = json.getString(DOCTYPE),
        nameSpaces = json.getJSONObject(NAMESPACES).let let1@{
            val nameSpaceKeys = it.keys()
            val result = mutableMapOf<String, MdocNameSpace>()
            while (nameSpaceKeys.hasNext()) {
                val key = nameSpaceKeys.next()
                result[key] = it.getJSONObject(key).let let2@{ nameSpacedDataJson ->
                    val nameSpacedDataKeys = nameSpacedDataJson.keys()
                    val data = mutableMapOf<String, MdocField>()
                    while (nameSpacedDataKeys.hasNext()) {
                        val fieldKey = nameSpacedDataKeys.next()
                        val fieldJson = nameSpacedDataJson.getJSONObject(fieldKey)
                        data[fieldKey] = MdocField(
                            value = fieldJson.opt(VALUE),
                            display = fieldJson.getString(DISPLAY),
                            displayValue = fieldJson.optString(DISPLAY_VALUE),
                        )
                    }
                    return@let2 MdocNameSpace(data)
                }
            }
            return@let1 result
        }
    )
}

data class MdocNameSpace(
    val data: Map<String, MdocField>,
)

data class MdocField(
    val value: Any?,
    val display: String,
    val displayValue: String?,
)

sealed class CredentialMetadata {
    companion object {
        fun fromJson(type: String, json: JSONObject): CredentialMetadata {
            return when (type) {
                VERIFICATION -> VerificationMetadata(
                    title = json.getString(TITLE),
                    subtitle = json.optString(SUBTITLE)
                )
                PAYMENT -> PaymentMetadata(
                    cardArt = json.getString(CARD_ART),
                    cardNetworkArt = json.getString(CARD_NETWORK_ART),
                )
                else -> throw IllegalArgumentException("$type of credential metadata is not supproted")
            }
        }
    }
}

data class PaymentMetadata(
    val cardArt: String, // b64 encoding
    val cardNetworkArt: String, // b64 encoding
): CredentialMetadata()

data class VerificationMetadata(
    val title: String,
    val subtitle: String?,
): CredentialMetadata()

private const val MSO_MDOC = "mso_mdoc"
private const val METADATA = "metadata"
private const val FORMAT = "format"
private const val CREDENTIAL = "credential"
private const val DOCTYPE = "docType"
private const val VALUE = "value"
private const val DISPLAY = "display"
private const val DISPLAY_VALUE = "display_value"
private const val NAMESPACES = "nameSpaces"
private const val VERIFICATION = "verification"
private const val PAYMENT = "payment"
private const val TITLE = "title"
private const val SUBTITLE = "subtitle"
private const val CARD_ART = "card_art"
private const val CARD_NETWORK_ART = "card_network_art"