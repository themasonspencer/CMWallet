package com.credman.cmwallet.pnv

import android.util.Base64
import android.util.Log
import androidx.credentials.provider.CallingAppInfo
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.CmWalletApplication.Companion.computeClientId
import com.credman.cmwallet.createJWTES256
import com.credman.cmwallet.getcred.GetCredentialActivity.DigitalCredentialRequestOptions
import com.credman.cmwallet.getcred.GetCredentialActivity.DigitalCredentialResult
import com.credman.cmwallet.jweSerialization
import com.credman.cmwallet.jwsDeserialization
import com.credman.cmwallet.loadECPrivateKey
import com.credman.cmwallet.openid4vp.OpenId4VP
import com.credman.cmwallet.openid4vp.OpenId4VP.Companion.IDENTIFIERS_1_0
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedCredential
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedMDocClaims
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedSdJwtClaims
import com.credman.cmwallet.pnv.PnvTokenRegistry.Companion.TEST_PNV_1_GET_PHONE_NUMBER
import com.credman.cmwallet.pnv.PnvTokenRegistry.Companion.TEST_PNV_1_VERIFY_PHONE_NUMBER
import com.credman.cmwallet.pnv.PnvTokenRegistry.Companion.TEST_PNV_2_GET_PHONE_NUMBER
import com.credman.cmwallet.pnv.PnvTokenRegistry.Companion.VCT_GET_PHONE_NUMBER
import com.credman.cmwallet.pnv.PnvTokenRegistry.Companion.VCT_VERIFY_PHONE_NUMBER
import com.credman.cmwallet.toJWK
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.interfaces.ECPrivateKey
import java.time.Instant

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
    val subscriptionHint: Int,
    val carrierHint: String,
    val phoneNumberHint: String?,
    val iss: String,
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
            phoneNumberHint = "+16502154321",
            iss = "https://example-carrier2.com",
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
            phoneNumberHint = "+16502157890",
            iss = "https://example-carrier2.com"
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

fun maybeHandlePnv(
    requestJson: String,
    providerIdx: Int,
    selectedID: String,
    dcqlCredId: String,
    origin: String, // Either the web origin or the calling app sha
    callingAppInfo: CallingAppInfo
): DigitalCredentialResult? {
    if (selectedID != TEST_PNV_1_GET_PHONE_NUMBER.tokenId && selectedID != TEST_PNV_2_GET_PHONE_NUMBER.tokenId) {
        return null
    }
    val digitalCredentialOptions = DigitalCredentialRequestOptions.createFrom(requestJson)
    val requestProtocol = DigitalCredentialRequestOptions.getRequestProtocolAtIndex(
        digitalCredentialOptions, providerIdx
    )
    val requestData: JSONObject = DigitalCredentialRequestOptions.getRequestDataAtIndex(
        digitalCredentialOptions, providerIdx
    )
    Log.i(PNV_TAG, "processDigitalCredentialOption protocol $requestProtocol")
    require(IDENTIFIERS_1_0.contains(requestProtocol)) {"Unsupported protocol identifier $requestProtocol"}
    val openId4VPRequest = OpenId4VP(requestData, computeClientId(callingAppInfo), requestProtocol)
    Log.i(PNV_TAG, "nonce ${openId4VPRequest.nonce}")

    val dcqlObject = openId4VPRequest.getDcqlCredentialObject(dcqlCredId)!!
    Log.i(PNV_TAG, "dqcl $dcqlObject")
    val vct = dcqlObject.getJSONObject("meta").getJSONArray("vct_values").let {
        for (i in 0..<it.length()) {
            val currVct = it.getString(i)
            if (currVct == VCT_GET_PHONE_NUMBER || currVct == VCT_VERIFY_PHONE_NUMBER) {
                return@let currVct
            }
        }
        throw IllegalStateException("Could not find a valid vct value for pnv")
    }

    val selectedCred = when (selectedID) {
        TEST_PNV_1_GET_PHONE_NUMBER.tokenId -> if (vct == TEST_PNV_1_GET_PHONE_NUMBER.vct) TEST_PNV_1_GET_PHONE_NUMBER else TEST_PNV_1_VERIFY_PHONE_NUMBER
        TEST_PNV_2_GET_PHONE_NUMBER.tokenId -> TEST_PNV_2_GET_PHONE_NUMBER
        else -> return null
    }

    val credAuthJwt = dcqlObject.getJSONObject("meta").getString("credential_authorization_jwt")
    val (credAuthJwtHeader, credAuthJwtpayload) = jwsDeserialization(credAuthJwt)

    require(credAuthJwtHeader.has("x5c")) { "Missing aggregator cert" }
    val aggregatorCertChain = credAuthJwtHeader.getJSONArray("x5c") // See the x5c cert chain defined at https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
    // TODO: validate the aggregator cert is allowed to request phone number verification for the given carrier

    val consentData = credAuthJwtpayload.optString("consent_data")
    // TODO: when the matcher renders the consent data, create the consent data digest to sign over
    // and prove that it has been displayed.
    val consentDataHash: String? = null

    val aggregatorNonce = credAuthJwtpayload.getString("nonce")
    require(aggregatorNonce == openId4VPRequest.nonce) { "Aggregator nonce should match the verifier nonce" }

    val aggregatorJwks = credAuthJwtpayload.getJSONObject("jwks").getJSONArray("keys")
    val aggregatorEncKey = aggregatorJwks.let {
        for (i in 0..<it.length()) {
            val jwk = it[i] as JSONObject
            if (jwk.has("use")
                && jwk["use"] == "enc"
                && jwk["kty"] == "EC"
                && jwk["crv"] == "P-256"
            ) {
                return@let jwk
            }
        }
        throw IllegalArgumentException("Given aggregator did not provide a valid encryption key")
    }

    // Generate the phone number token SD-JWT
    val tempTokenJson = buildJsonObject {
        put("iss", selectedCred.iss)
        put("vct", selectedCred.vct)
        put("temp_token", getTempTokenForCredential(selectedCred))
        put("subscription_hint", selectedCred.subscriptionHint)
        put("carrier_hint", selectedCred.carrierHint)
    }
    val encryptedTempTokenJwe = jweSerialization(aggregatorEncKey, tempTokenJson.toString())

    val tmpKey =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6ef4-enmfQHRWUW40-Soj3aFB0rsEOp3tYMW-HJPBvChRANCAAT5N1NLZcub4bOgWfBwF8MHPGkfJ8Dm300cioatq9XovaLgG205FEXUOuNMEMQuLbrn8oiOC0nTnNIVn-OtSmSb"
    val privateKey =
        loadECPrivateKey(Base64.decode(tmpKey, Base64.URL_SAFE)) as ECPrivateKey
    val tempTokenDcJwt = createJWTES256(
        header = buildJsonObject {
            put("alg", "ES256")
        },
        payload = buildJsonObject {
            put("nonce", openId4VPRequest.nonce)
            put("origin", origin)
            put("encrypted_credential", encryptedTempTokenJwe)
        },
        privateKey = privateKey
    )

    // We don't use selective disclosure, so the sd-jwt is simply jwt + "~"
    val tempTokenDcSdJwt = "${tempTokenDcJwt}~"

    val vpToken = JSONObject().apply {
        put(dcqlCredId, tempTokenDcSdJwt)
    }
    val response = openId4VPRequest.generateResponse(vpToken)
    Log.d(PNV_TAG, "Returning $response")

    return DigitalCredentialResult(
        responseJsonLegacy = "",
        authenticationTitle = "",
        authenticationSubtitle = null,
        responseJsonModern = JSONObject().apply {
            put("protocol", openId4VPRequest.protocolIdentifier)
            put("data", JSONObject(response))
        }.toString()
    )
}

fun getTempTokenForCredential(cred: PnvTokenRegistry): String {
    return "TODO: generate temp token"
}

private const val PNV_TAG = "PnvHandler"