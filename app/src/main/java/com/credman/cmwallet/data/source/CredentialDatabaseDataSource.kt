package com.credman.cmwallet.data.source

import android.util.Log
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.data.model.CredentialItem
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.transform

class CredentialDatabaseDataSource {
    val credentialDao = CmWalletApplication
        .database
        .credentialDao()

    val credentials: Flow<List<CredentialItem>> = credentialDao
        .getAll()
        .transform { list ->
            emit(list.map { it.toCredentialItem() })
        }

    fun getCredential(id: String): CredentialItem? {
        return try {
            credentialDao.loadCredById(id.toLong())?.toCredentialItem()
        } catch (e: Exception) {
            Log.e(CmWalletApplication.TAG, "database retrieval error", e)
            null
        }
    }
}