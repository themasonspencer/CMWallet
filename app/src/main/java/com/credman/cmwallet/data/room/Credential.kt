package com.credman.cmwallet.data.room

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey
import com.credman.cmwallet.data.model.CredentialItem
import kotlinx.serialization.json.Json

@Entity
data class Credential(
    @PrimaryKey(autoGenerate = false) @ColumnInfo(name = "id") val id: String,
    @ColumnInfo(name = "credentialItemJson") val credentialItemJson: String,
) {
    val credentialItem: CredentialItem
        get() = run {
            val json = Json {
                explicitNulls = false
                ignoreUnknownKeys = true
            }
            json.decodeFromString(credentialItemJson)
        }

//    fun toCredentialItem(): CredentialItem {
//        val json = Json {
//            explicitNulls = false
//            ignoreUnknownKeys = true
//        }
//        return json.decodeFromString(credentialItemJson)
//    }
}

