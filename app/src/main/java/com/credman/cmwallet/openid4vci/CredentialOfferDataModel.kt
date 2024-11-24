package com.credman.cmwallet.openid4vci

import org.json.JSONObject

data class CredConfigsSupportedDisplay(
    val name: String,
    val locale: String? = null,
    val logo: CredConfigsSupportedDisplayLogo? = null,
    val description: String? = null,
    val backgroundColor: String? = null,
    // `https:` or `data:` scheme
    val backgroundImage: String? = null,
    val textColor: String,
) {
    constructor(json: JSONObject) : this(
        name = json.getString(NAME),
        locale = json.optString(LOCALE),
        logo = json.optJSONObject(LOGO)?.let {
            CredConfigsSupportedDisplayLogo(
                uri = it.getString(URI),
                altText = it.optString(ALT_TEXT)
            )
        },
        description = json.optString(DESCRIPTION),
        backgroundColor = json.optString(BACKGROUND_COLOR),
        backgroundImage = json.optJSONObject(BACKGROUND_IMAGE)?.getString(URI),
        textColor = json.optString(TEXT_COLOR),
    )
}

private fun JSONObject.getDisplays(): List<CredConfigsSupportedDisplay>? =
    this.optJSONArray(DISPLAY)?.let {
        val out = mutableListOf<CredConfigsSupportedDisplay>()
        for (i in 0..<it.length()) {
            out.add(CredConfigsSupportedDisplay(it.getJSONObject(i)))
        }
        out
    }

data class CredConfigsSupportedDisplayLogo(
    val uri: String,
    val altText: String?
)

sealed class CredConfigsSupportedItem(
    val format: String,
    val cryptographicBindingMethodsSupported: List<String>? = null,
    val credentialSigningAlgValuesSupported: List<String>? = null,
    val display: List<CredConfigsSupportedDisplay>? = null,
) {
    companion object {
        fun createFrom(json: JSONObject): CredConfigsSupportedItem {
            return if (json.has(DOCTYPE)) {
                MdocCredConfigsSupportedItem(json)
            } else {
                UnknownCredConfigsSupportedItem(json)
            }
        }
    }
}

class UnknownCredConfigsSupportedItem(
    format: String,
    cryptographicBindingMethodsSupported: List<String>? = null,
    credentialSigningAlgValuesSupported: List<String>? = null,
    display: List<CredConfigsSupportedDisplay>? = null,
) : CredConfigsSupportedItem(
    format,
    cryptographicBindingMethodsSupported,
    credentialSigningAlgValuesSupported,
    display
) {
    constructor(json: JSONObject) : this(
        format = json.getString(FORMAT),
        cryptographicBindingMethodsSupported = json.getCryptographicBindingMethodsSupported(),
        credentialSigningAlgValuesSupported = json.getCredentialSigningAlgValuesSupported(),
        display = json.getDisplays(),
    )
}

class MdocCredConfigsSupportedItem(
    format: String,
    cryptographicBindingMethodsSupported: List<String>? = null,
    credentialSigningAlgValuesSupported: List<String>? = null,
    display: List<CredConfigsSupportedDisplay>? = null,
    val doctype: String,
    // Namespace as key e.g. "org.iso.18013.5.1"
    val claims: Map<String, NamespacedClaims>?,
) : CredConfigsSupportedItem(
    format,
    cryptographicBindingMethodsSupported,
    credentialSigningAlgValuesSupported,
    display
) {
    constructor(json: JSONObject) : this(
        format = json.getString(FORMAT),
        cryptographicBindingMethodsSupported = json.getCryptographicBindingMethodsSupported(),
        credentialSigningAlgValuesSupported = json.getCredentialSigningAlgValuesSupported(),
        display = json.getDisplays(),
        doctype = json.getString(DOCTYPE),
        claims = json.optJSONObject(CLAIMS)?.let {
            val keys = it.keys()
            val out = mutableMapOf<String, NamespacedClaims>()
            while (keys.hasNext()) {
                val key = keys.next()
                out[key] = NamespacedClaims(it.getJSONObject(key))
            }
            out
        }
    )
}

data class NamespacedClaims(
    val values: Map<String, Claim>
) {
    constructor(json: JSONObject) : this(
        values = json.let {
            val keys = it.keys()
            val out = mutableMapOf<String, Claim>()
            while (keys.hasNext()) {
                val key = keys.next()
                out[key] = Claim(it.getJSONObject(key))
            }
            out
        }
    )
}

data class Claim(
    val display: List<ClaimDisplay>? = null,
    val mandatory: Boolean = false,
    val valueType: String? = null,
) {
    constructor(json: JSONObject) : this(
        display = json.optJSONArray(DISPLAY)?.let {
            val out = mutableListOf<ClaimDisplay>()
            for (i in 0..<it.length()) {
                out.add(ClaimDisplay(it.getJSONObject(i)))
            }
            out
        },
        mandatory = json.optBoolean(MANDATORY, false),
        valueType = json.optString(VALUE_TYPE),
    )
}

data class ClaimDisplay(
    val name: String?,
    val locale: String?,
) {
    constructor(json: JSONObject) : this(json.optString(NAME), json.optString(LOCALE))
}

private fun JSONObject.getCryptographicBindingMethodsSupported(): List<String>? =
    this.optJSONArray(CRYPTOGRAPHIC_BINDING_METHODS_SUPPORTED)?.let {
        val out = mutableListOf<String>()
        for (i in 0..<it.length()) {
            out.add(it.getString(i))
        }
        out
    }

private fun JSONObject.getCredentialSigningAlgValuesSupported(): List<String>? =
    this.optJSONArray(CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED)?.let {
        val out = mutableListOf<String>()
        for (i in 0..<it.length()) {
            out.add(it.getString(i))
        }
        out
    }


internal const val CREDENTIAL_ISSUER = "credential_issuer"
internal const val CREDENTIAL_CONFIGURATION_IDS = "credential_configuration_ids"
internal const val ISSUER_METADATA = "issuer_metadata"
internal const val CREDENTIAL_CONFIGURATION_SUPPORTED = "credential_configurations_supported"
internal const val CRYPTOGRAPHIC_BINDING_METHODS_SUPPORTED =
    "cryptographic_binding_methods_supported"
internal const val CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED =
    "credential_signing_alg_values_supported"
internal const val FORMAT = "format"
internal const val DOCTYPE = "doctype"
internal const val DISPLAY = "display"
internal const val NAME = "name"
internal const val URI = "uri"
internal const val LOCALE = "locale"
internal const val MANDATORY = "mandatory"
internal const val LOGO = "logo"
internal const val DESCRIPTION = "description"
internal const val CLAIMS = "claims"
internal const val BACKGROUND_IMAGE = "background_image"
internal const val BACKGROUND_COLOR = "background_color"
internal const val TEXT_COLOR = "text_color"
internal const val VALUE_TYPE = "value_type"
internal const val ALT_TEXT = "alt_text"
internal const val CREDENTIAL_ENDPOINT = "credential_endpoint"
internal const val NONCE_ENDPOINT = "nonce_endpoint"
const val PROTOCOL = "protocol"
const val DATA = "data"