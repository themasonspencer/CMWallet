package com.credman.cmwallet.data.room

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey
import com.credman.cmwallet.data.model.CredentialItem
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Entity(tableName = "credentials")
data class CredentialDatabaseItem(
    @PrimaryKey(autoGenerate = false) @ColumnInfo(name = "id") val id: String,
    @ColumnInfo(name = "credentialItemJson") val credentialItemJson: String,
) {
    constructor(item: CredentialItem) : this(item.id, Json.encodeToString(item))

    val credentialItem: CredentialItem
        get() = run {
            val json = Json {
                explicitNulls = false
                ignoreUnknownKeys = true
            }
            json.decodeFromString(credentialItemJson)
        }
}

