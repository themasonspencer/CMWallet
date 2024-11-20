package com.credman.cmwallet.openid4vp

import android.util.Base64
import android.util.Log
import com.credman.cmwallet.cbor.CborTag
import com.credman.cmwallet.cbor.cborEncode
import com.credman.cmwallet.data.model.CredentialItem
import org.json.JSONObject
import java.security.MessageDigest

data class TransactionData(
    val encodedData: String,
    val type: String,
    val credentialIds: List<String>,
    val data: JSONObject
)

class OpenId4VP(val request: String) {
    val requestJson: JSONObject = JSONObject(request)

    val nonce: String
    val clientId: String // TODO: parse out the scheme
    val dcqlQuery: JSONObject
    val transactionData: List<TransactionData>

    init {
        // Parse required params
        require(requestJson.has("client_id")) { "Authorization Request must contain a client_id" }
        require(requestJson.has("nonce")) { "Authorization Request must contain a nonce" }
        require(requestJson.has("dcql_query")) { "Authorization Request must contain a dcql_query" }

        clientId = requestJson.getString("client_id")
        nonce = requestJson.getString("nonce")
        dcqlQuery = requestJson.getJSONObject("dcql_query")

        val transactionDataJson = requestJson.optJSONArray("transaction_data")
        if (transactionDataJson != null) {
            val tempList = mutableListOf<TransactionData>()
            for (i in 0 until transactionDataJson.length()) {
                val transactionDataItemEncoded = transactionDataJson.getString(i)
                val transactionDataItemJson = Base64.decode(transactionDataItemEncoded, Base64.URL_SAFE ).toString(Charsets.UTF_8)
                val transactionDataItem = JSONObject(transactionDataItemJson)
                val credentialIds = mutableListOf<String>()
                val credentialIdsJson = transactionDataItem.getJSONArray("credential_ids")
                for (j in 0 until  credentialIdsJson.length()) {
                    credentialIds.add(credentialIdsJson.getString(j))
                }

                tempList.add(TransactionData(
                    transactionDataItemEncoded,
                    transactionDataItem.getString("type"),
                    credentialIds,
                    transactionDataItem
                ))
            }
            transactionData = tempList
        } else {
            transactionData = emptyList()
        }

    }

    fun generateDeviceSignedTransactionData(dcqlId: String): Map<String, List<ByteArray>> {
        if (transactionData.isEmpty()) {
            return emptyMap()
        }
        val transactionDataHashes = mutableListOf<ByteArray>()
        for (transactionDataItem in transactionData) {
            if (dcqlId in transactionDataItem.credentialIds) {
                val md = MessageDigest.getInstance("SHA-256")
                transactionDataHashes.add(md.digest(transactionDataItem.encodedData.encodeToByteArray()))
            }
        }
        return mapOf(Pair(
            "transaction_data_hashes",
            transactionDataHashes.toList()
        ))
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