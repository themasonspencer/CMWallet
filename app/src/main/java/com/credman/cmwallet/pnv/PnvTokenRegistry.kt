package com.credman.cmwallet.pnv

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * A phone number verification entry to be registered with the Credential Manager.
 *
 * @param tokenId The Securely generated ID that will be used to identify a user selection
 * @param title The display title for this TS43 token entry. Ideally this should be an obfuscated
 *   phone number, such as ***-***-1234, or some other information that allows the user to
 *   disambiguate this entry from others, especially in the multi-sim use case.
 * @param subscriptionId The subscription ID of the SIM card that this token is associated with.
 * @param carrierId The carrier ID of the SIM card that this token is associated with.
 * @param useCases The set of use cases that this token is. Allowed values are:
 *   [USE_CASE_VERIFY_PHONE_NUMBER], [USE_CASE_GET_PHONE_NUMBER], [USE_CASE_GET_SUBSCRIBER_INFO]
 */
data class PnvTokenRegistry(
    val tokenId: String,
    val vct: String,
    val title: String,
    val providerConsent: String?,
    val subscriptionHint: Int?,
    val carrierHint: String?,
    val phoneNumberHint: String?
) {
    /** Converts this TS43 entry to the more generic SD-JWT registry item(s). */
    private fun toSdJwtRegistryItems(): SdJwtRegistryItem {
        return SdJwtRegistryItem(
                id = tokenId,
                vct = vct,
                claims =
                    listOf(
                        RegistryClaim("subscription_hint", null, subscriptionHint),
                        RegistryClaim("carrier_hint", null, carrierHint),
                        RegistryClaim("phone_number_hint", null, phoneNumberHint),
                    ),
                displayData = ItemDisplayData(title = title, subtitle = null, description = providerConsent),
            )
    }

    companion object {
        const val VCT_GET_PHONE_NUMBER = "number-verification/device-phone-number/ts43"
        const val VCT_VERIFY_PHONE_NUMBER = "number-verification/verify/ts43"
        const val PNV_CRED_FORMAT = "dc+sd-jwt-pnv"

        internal const val CREDENTIALS = "credentials"
        internal const val ID = "id"
        internal const val TITLE = "title"
        internal const val SUBTITLE = "subtitle"
        internal const val DISCLAIMER = "disclaimer"
        internal const val PATHS = "paths"
        internal const val VALUE = "value"
        internal const val DISPLAY = "display"

        val TEST_PNV_1_GET_PHONE_NUMBER = PnvTokenRegistry(
            tokenId = "pnv_1",
            vct = VCT_GET_PHONE_NUMBER,
            title = "Phone Number",
            providerConsent = "CMWallet will enable your carrier {carrier name} to share your phone number iwth {app/domain name}",
            subscriptionHint = 1,
            carrierHint = "310250",
            phoneNumberHint = "+16502154321"
        )
        val TEST_PNV_1_VERIFY_PHONE_NUMBER = TEST_PNV_1_GET_PHONE_NUMBER.copy(
            vct = VCT_VERIFY_PHONE_NUMBER,
        )
        val TEST_PNV_2_GET_PHONE_NUMBER = PnvTokenRegistry(
            tokenId = "pnv_2",
            vct = VCT_GET_PHONE_NUMBER,
            title = "Phone Number",
            providerConsent = "CMWallet will enable your carrier MOCK-CARRIER-2 to share your phone number",
            subscriptionHint = 2,
            carrierHint = "380250",
            phoneNumberHint = "+16502157890"
        )

        fun buildRegistryDatabase(items: List<PnvTokenRegistry>): ByteArray {
            val out = ByteArrayOutputStream()

            // We don't support icon for phone number tokens, yet
            // Write the offset to the json
            val jsonOffset = 4
            val buffer = ByteBuffer.allocate(4)
            buffer.order(ByteOrder.LITTLE_ENDIAN)
            buffer.putInt(jsonOffset)
            out.write(buffer.array())

            val sdJwtCredentials = JSONObject()
            for (item in items.map { it.toSdJwtRegistryItems() }) {
                val credJson = JSONObject()
                credJson.put(ID, item.id)
                credJson.put(TITLE, item.displayData.title)
                credJson.putOpt(SUBTITLE, item.displayData.subtitle)
                credJson.putOpt(DISCLAIMER, item.displayData.description)
                val paths = JSONObject()
                for (claim in item.claims) {
                    paths.put(claim.path, JSONObject().putOpt(DISPLAY, claim.display).putOpt(VALUE, claim.value))
                }

                credJson.put(PATHS, paths)
                val vctType = item.vct
                when (val current = sdJwtCredentials.opt(vctType) ?: JSONArray()) {
                    is JSONArray -> sdJwtCredentials.put(vctType, current.put(credJson))
                    else -> throw IllegalStateException("Unexpected type ${current::class.java}")
                }
            }
            val registryCredentials = JSONObject()
            registryCredentials.put(PNV_CRED_FORMAT, sdJwtCredentials)
            val registryJson = JSONObject()
            registryJson.put(CREDENTIALS, registryCredentials)
            out.write(registryJson.toString().toByteArray())
            return out.toByteArray()
        }
    }
}

private class RegistryClaim(
    val path: String, // Single depth only
    val display: String?,
    val value: Any?,
)

private class ItemDisplayData(val title: String, val subtitle: String?, val description: String?)

private class SdJwtRegistryItem(
    val id: String,
    val vct: String,
    val claims: List<RegistryClaim>,
    val displayData: ItemDisplayData,
)