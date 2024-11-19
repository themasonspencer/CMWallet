package com.credman.cmwallet.openid4vp

import com.credman.cmwallet.cbor.CborTag
import com.credman.cmwallet.cbor.cborEncode
import com.credman.cmwallet.data.model.CredentialItem
import org.json.JSONObject
import java.security.MessageDigest

class OpenId4VP(val request: String) {
    val requestJson: JSONObject = JSONObject(request)

    val nonce: String
    val clientId: String // TODO: parse out the scheme
    val dcqlQuery: JSONObject

    init {
        // Parse required params
        require(requestJson.has("client_id")) { "Authorization Request must contain a client_id" }
        require(requestJson.has("nonce")) { "Authorization Request must contain a nonce" }
        require(requestJson.has("dcql_query")) { "Authorization Request must contain a dcql_query" }

        clientId = requestJson.getString("client_id")
        nonce = requestJson.getString("nonce")
        dcqlQuery = requestJson.getJSONObject("dcql_query")
    }

    fun matchCredentials(credentialStore: JSONObject): Map<String, List<MatchedCredential>> {
        return DCQLQuery(dcqlQuery, credentialStore)
    }

    fun performQueryOnCredential(selectedCredential: CredentialItem): OpenId4VPMatchedCredential {
        return performQueryOnCredential(dcqlQuery, selectedCredential)
    }

    fun getHandover(origin: String): List<Any> {
        val handoverData = listOf(
            clientId,
            nonce,
            origin
        )

        val md = MessageDigest.getInstance("SHA-256")
        return listOf(
            "OID4VPDCAPIHandover",
            md.digest(cborEncode(CborTag(24, cborEncode(handoverData))))
        )
    }
}