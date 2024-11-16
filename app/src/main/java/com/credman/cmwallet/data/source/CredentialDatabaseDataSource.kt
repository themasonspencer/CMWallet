package com.credman.cmwallet.data.source

import com.credman.cmwallet.data.model.CredentialItem
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class CredentialDatabaseDataSource {

    // TODO: Make this a Room database, for now just return an empty list
    private val _credentials = MutableStateFlow(emptyList<CredentialItem>())
    val credentials: StateFlow<List<CredentialItem>> = _credentials.asStateFlow()
}