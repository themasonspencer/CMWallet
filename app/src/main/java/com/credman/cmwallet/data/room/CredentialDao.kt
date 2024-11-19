package com.credman.cmwallet.data.room

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface CredentialDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(vararg creds: Credential)

    @Update
    suspend fun updateUsers(vararg creds: Credential)

    @Delete
    suspend fun delete(cred: Credential)

    @Query("SELECT * FROM credential")
    fun getAll(): Flow<List<Credential>>

    @Query("SELECT * FROM credential WHERE id = :id")
    fun loadCredById(id: Long): Credential?
}