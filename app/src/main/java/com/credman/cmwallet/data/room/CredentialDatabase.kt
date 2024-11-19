package com.credman.cmwallet.data.room

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(entities = [Credential::class], version = 1)
abstract class CredentialDatabase : RoomDatabase() {
    abstract fun credentialDao(): CredentialDao
}