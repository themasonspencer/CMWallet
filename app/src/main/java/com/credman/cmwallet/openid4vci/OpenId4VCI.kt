package com.credman.cmwallet.openid4vci

import org.json.JSONObject

class OpenId4VCI(val request: String) {
    val requestJson: JSONObject = JSONObject(request)

    val credentialIssuer: String
    val credentialConfigurationIds: List<String>
    val credentialConfigurationsSupportedMap: Map<String, CredConfigsSupportedItem>

    init {
        require(requestJson.has(CREDENTIAL_ISSUER)) { "Issuance request must contain $CREDENTIAL_ISSUER" }
        require(requestJson.has(CREDENTIAL_CONFIGURATION_IDS)) { "Issuance request must contain $CREDENTIAL_CONFIGURATION_IDS" }
        // This should be required for the DC API browser profile
        require(requestJson.has(ISSUER_METADATA)) { "Issuance request must contain $ISSUER_METADATA" }

        credentialIssuer = requestJson.getString(CREDENTIAL_ISSUER)
        credentialConfigurationIds = requestJson.getJSONArray(CREDENTIAL_CONFIGURATION_IDS).let {
            val ids = mutableListOf<String>()
            for (i in 0..<it.length()) {
                ids.add(it.getString(i))
            }
            ids
        }

        val issuerMetadataJson = requestJson.getJSONObject(ISSUER_METADATA)
        require(issuerMetadataJson.has(CREDENTIAL_CONFIGURATION_SUPPORTED)) { "Issuance request must contain $CREDENTIAL_CONFIGURATION_SUPPORTED" }
        val credConfigSupportedJson = issuerMetadataJson.getJSONObject(CREDENTIAL_CONFIGURATION_SUPPORTED)
        val itr = credConfigSupportedJson.keys()
        val tmpMap = mutableMapOf<String, CredConfigsSupportedItem>()
        while (itr.hasNext()) {
            val configId = itr.next()
            val item = credConfigSupportedJson.getJSONObject(configId)
            tmpMap[configId] = CredConfigsSupportedItem.createFrom(credConfigSupportedJson.getJSONObject(configId))
        }
        credentialConfigurationsSupportedMap = tmpMap
    }
}