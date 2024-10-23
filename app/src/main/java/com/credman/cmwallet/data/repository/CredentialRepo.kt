package com.credman.cmwallet.data.repository

import com.credman.cmwallet.data.model.CredentialItem
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.asFlow

class CredentialRepo {
    fun getCredentials(): List<CredentialItem> {
        return emptyList<CredentialItem>()
    }
}