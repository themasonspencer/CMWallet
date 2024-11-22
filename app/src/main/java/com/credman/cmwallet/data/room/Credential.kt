package com.credman.cmwallet.data.room

import android.util.Log
import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey
import com.credman.cmwallet.data.model.CredentialItem
import org.json.JSONObject

@Entity
data class Credential(
    @PrimaryKey(autoGenerate = true) @ColumnInfo(name = "id") val id: Long = 0,
    @ColumnInfo(name = "credJson") val credJson: String,
) {
    fun toCredentialItem(): CredentialItem = CredentialItem(
        id = id.toString(),
        json = JSONObject(credJson),
    )
}

