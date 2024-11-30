package com.credman.cmwallet.data.source

import com.credman.cmwallet.data.model.CredentialItem
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.json.Json

// Static test credentials loaded from a json string
class TestCredentialsDataSource {
    private val _credentials = MutableStateFlow(emptyList<CredentialItem>())
    val credentials: StateFlow<List<CredentialItem>> = _credentials.asStateFlow()
    private val json = Json {
        explicitNulls = false
        ignoreUnknownKeys = true
    }

    fun initWithJson(credentialsJson: String) {
        _credentials.update {
            json.decodeFromString(credentialsJson)
        }
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