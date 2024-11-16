package com.credman.cmwallet.data.repository

import android.util.Base64
import android.util.Log
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.model.MSO_MDOC
import com.credman.cmwallet.data.model.MdocCredential
import com.credman.cmwallet.data.source.CredentialDatabaseDataSource
import com.credman.cmwallet.data.source.TestCredentialsDataSource
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

object CredentialRepository {
    private val testCredentialsDataSource = TestCredentialsDataSource()
    private val credentialDatabaseDataSource = CredentialDatabaseDataSource()

    private fun combinedCredentials(): Flow<List<CredentialItem>> = flow {
        emitAll(
            combine(
                testCredentialsDataSource.credentials,
                credentialDatabaseDataSource.credentials
            ) { list1, list2 ->
                list1 + list2
            })
    }

    val credentials: Flow<List<CredentialItem>> = combinedCredentials()

    val credentialRegistryDatabase: Flow<ByteArray> = flow {
        emitAll(combinedCredentials().map { credentials ->
            Log.i("CredentialRepository", "Updating flow with ${credentials.size}")
            createRegistryDatabase(credentials)
        })
    }

    fun addCredentialsFromJson(credentialJson: String) {
        testCredentialsDataSource.initWithJson(credentialJson)
    }

    fun getCredential(id: String): CredentialItem? {
        // TODO: check credentialDatabaseDataSource too
        return testCredentialsDataSource.getCredential(id)
    }

    class RegistryIcon(
        val iconValue: ByteArray,
        var iconOffset: Int = 0
    )

    /**
     * Credential Registry has the following format:
     *
     * |---------------------------------------|
     * |--- (Int) offset of credential json ---|
     * |--------- (Byte Array) Icon 1 ---------|
     * |--------- (Byte Array) Icon 2 ---------|
     * |------------- More Icons... -----------|
     * |----------- Credential Json -----------|  // See assets/paymentcreds.json as an example
     * |---------------------------------------|
     */
    private fun createRegistryDatabase(items: List<CredentialItem>): ByteArray {
        val out = ByteArrayOutputStream()

        val iconMap: Map<String, RegistryIcon> = items.associate {
            Pair(
                it.id,
                RegistryIcon(Base64.decode(it.metadata.icon, 0))
            )
        }
        // Write the offset to the json
        val jsonOffset = 4 + iconMap.values.sumOf { it.iconValue.size }
        val buffer = ByteBuffer.allocate(4)
        buffer.order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(jsonOffset)
        out.write(buffer.array())

        // Write the icons
        var currIconOffset = 4
        iconMap.values.forEach {
            it.iconOffset = currIconOffset
            out.write(it.iconValue)
            currIconOffset += it.iconValue.size
        }

        val mdocCredentials = JSONObject()
        items.forEach { item ->
            when (item.credential) {
                is MdocCredential -> {
                    val credJson = JSONObject()
                    credJson.put(ID, item.id)
                    credJson.put(TITLE, item.metadata.title)
                    credJson.putOpt(SUBTITLE, item.metadata.subtitle)
                    val iconJson = JSONObject().apply {
                        put(START, iconMap[item.id]!!.iconOffset)
                        put(LENGTH, iconMap[item.id]!!.iconValue.size)
                    }
                    credJson.put(ICON, iconJson)
                    if (item.credential.nameSpaces.isNotEmpty()) {
                        val namespacesJson = JSONObject()
                        item.credential.nameSpaces.forEach { namespace ->
                            val namespaceJson = JSONObject()
                            namespace.value.data.forEach { namespaceData ->
                                val namespaceDataJson = JSONObject()
                                namespaceDataJson.putOpt(VALUE, namespaceData.value.value)
                                namespaceDataJson.put(DISPLAY, namespaceData.value.display)
                                namespaceDataJson.putOpt(
                                    DISPLAY_VALUE,
                                    namespaceData.value.displayValue
                                )
                                namespaceJson.put(namespaceData.key, namespaceDataJson)
                            }
                            namespacesJson.put(namespace.key, namespaceJson)
                        }
                        credJson.put(NAMESPACES, namespacesJson)
                    }
                    mdocCredentials.accumulate(item.credential.docType, credJson)
                }
            }
        }
        val registryCredentials = JSONObject()
        registryCredentials.put(MSO_MDOC, mdocCredentials)
        val registryJson = JSONObject()
        registryJson.put(CREDENTIALS, registryCredentials)
        out.write(registryJson.toString().toByteArray())
        return out.toByteArray()
    }

    // Wasm database json keys
    const val CREDENTIALS = "credentials"
    const val ID = "id"
    const val TITLE = "title"
    const val SUBTITLE = "subtitle"
    const val ICON = "icon"
    const val START = "start"
    const val LENGTH = "length"
    const val NAMESPACES = "namespaces"
    const val VALUE = "value"
    const val DISPLAY = "display"
    const val DISPLAY_VALUE = "display_value"
}