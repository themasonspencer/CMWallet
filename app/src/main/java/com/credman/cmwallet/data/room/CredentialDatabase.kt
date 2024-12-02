package com.credman.cmwallet.data.room

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(entities = [CredentialDatabaseItem::class], version = 3)
abstract class CredentialDatabase : RoomDatabase() {
    abstract fun credentialDao(): CredentialDao
}