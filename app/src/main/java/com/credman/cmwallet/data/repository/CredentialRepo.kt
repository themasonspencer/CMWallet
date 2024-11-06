package com.credman.cmwallet.data.repository

import android.content.Context
import com.credman.cmwallet.data.model.CredentialItem
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.asFlow
import org.json.JSONObject

class CredentialRepo {
    fun getCredentials(context: Context): List<CredentialItem> {
        return getCredentialsFromJsonAsset(context)
    }

    private fun getCredentialsFromJsonAsset(context: Context): List<CredentialItem> {
        val stream = context.assets.open("database.json")
        val reader = stream.bufferedReader()
        val credsDatabase = reader.use { it.readText() }
        reader.close()
        val credsJson = JSONObject(credsDatabase)
        val credKeys = credsJson.keys()
        val result = mutableListOf<CredentialItem>()
        while (credKeys.hasNext()) {
            val credKey = credKeys.next()
            val cred = credsJson.getJSONObject(credKey)
            result.add(
                CredentialItem(
                    id = credKey,
                    json = cred,
                )
            )
        }
        return result
    }
}