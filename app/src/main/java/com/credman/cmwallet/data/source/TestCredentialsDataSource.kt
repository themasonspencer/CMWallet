package com.credman.cmwallet.data.source

import com.credman.cmwallet.data.model.CredentialItem
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.json.JSONObject

// Static test credentials loaded from a json string
class TestCredentialsDataSource {
    private val _credentials = MutableStateFlow(emptyList<CredentialItem>())
    val credentials: StateFlow<List<CredentialItem>> = _credentials.asStateFlow()

    fun initWithJson(credentialsJson: String) {
        val credentialsDict = JSONObject(credentialsJson)
        val credentialsIds = credentialsDict.keys()
        val credentialsList = mutableListOf<CredentialItem>()
        credentialsIds.forEach { credentialId ->
            val credential = credentialsDict.getJSONObject(credentialId)
            credentialsList.add(
                CredentialItem(
                    id = credentialId,
                    json = credential,
                )
            )
        }
        _credentials.update { credentialsList.toList() }
    }

    fun getCredential(id: String): CredentialItem? {
        credentials.value.forEach {
            if (it.id == id) {
                return it
            }
        }
        return null
    }
}