package com.credman.cmwallet.mdoc

import android.net.Uri
import android.util.Log
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.cbor.CborTag
import com.credman.cmwallet.cbor.cborDecode
import com.credman.cmwallet.cbor.cborEncode
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.model.MSO_MDOC
import com.credman.cmwallet.data.model.MdocCredential
import com.credman.cmwallet.data.model.MdocField
import com.credman.cmwallet.data.model.MdocNameSpace
import com.credman.cmwallet.data.model.PAYMENT_CARD_DOC_TYPE
import com.credman.cmwallet.data.model.PaymentMetadata
import com.credman.cmwallet.data.model.VerificationMetadata
import com.credman.cmwallet.openid4vci.CredConfigsSupportedItem
import com.credman.cmwallet.openid4vci.DATA
import com.credman.cmwallet.openid4vci.MdocCredConfigsSupportedItem
import java.security.PrivateKey
import java.security.Signature

fun createSessionTranscript(handover: Any): ByteArray {
    val sessionTranscript = listOf(
        null,
        null,
        handover
    )
    return cborEncode(CborTag(24, cborEncode(sessionTranscript)))
}

fun toCredentialItem(
    issuerSigned: ByteArray,
    deviceKey: PrivateKey,
    credentialConfiguration: CredConfigsSupportedItem,
): CredentialItem {
    require(credentialConfiguration is MdocCredConfigsSupportedItem) { "Credential configuration should be"}
    require(credentialConfiguration.format == MSO_MDOC) { "Expect mdo_mdoc format but got ${credentialConfiguration.format}"}
    val issuerSignedDict = cborDecode(issuerSigned) as Map<*, *>
    val doctype = credentialConfiguration.doctype
    val claims = credentialConfiguration.claims
    val issuerSignedNamespaces = (issuerSignedDict.toMutableMap()["nameSpaces"] as Map<String, *>)
    val nameSpaces: Map<String, MdocNameSpace> = issuerSignedNamespaces.mapValues { (key, value) ->
        Log.d(TAG, "Processing namespacedData for namespace $key")
        val issuerSignedElements = value as List<*>
        Log.d(TAG, "Keys ${claims?.keys}")
        val namespacedClaims = claims!![key]!!
        val namespacedData = mutableMapOf<String, MdocField>()
        issuerSignedElements.forEach { element ->
            if (element is CborTag) {
                val elementDict = cborDecode(element.item as ByteArray) as Map<*, *>
                val elementIdentifier = elementDict[ELEMENT_IDENTIFYIER] as String
                val elementValue = elementDict[ELEMENT_VALUE] as Any
                val elementDisplay = namespacedClaims.values[elementIdentifier]?.display?.firstOrNull()
                if (elementDisplay?.name == null) {
                    Log.w(TAG, "Skipping element $elementIdentifier because it doesn't have a display value")
                } else {
                    namespacedData[elementIdentifier] = MdocField(
                        value = elementValue,
                        display = elementDisplay.name,
                        displayValue = elementValue.toString() // TODO: This technically isn't right but we can't get this display value from elsewhere.
                    )
                }
            }
        }
        Log.d(TAG, "Added namespacedData for namespace $key: $namespacedData")
        return@mapValues MdocNameSpace(data = namespacedData)
    }
    val cred = MdocCredential(
        docType = doctype,
        nameSpaces = nameSpaces,
        deviceKey = deviceKey,
        issuerSigned = issuerSigned
    )

    val regex = "image/.*,".toRegex()
    val title = credentialConfiguration.display?.firstOrNull()?.name
    val subtitle = credentialConfiguration.display?.firstOrNull()?.description
    val itemIcon = credentialConfiguration.display?.firstOrNull()?.backgroundImage?.let {
        val imageUri = Uri.parse(it)
        require(imageUri.scheme == DATA) { "only image data scheme is supported for now"}
        val ssp = Uri.parse(it).schemeSpecificPart
        ssp.replace(regex, "")
    }
    val credMetadata = when (doctype) {
        PAYMENT_CARD_DOC_TYPE -> PaymentMetadata(
            title = title ?: "Payment Card",
            subtitle = subtitle,
            icon = itemIcon,
            cardNetworkArt = null,
        )
        else -> VerificationMetadata(
            title = title ?: "Card",
            subtitle = subtitle,
            icon = itemIcon
        )
    }

    return CredentialItem(
        id = 0L.toString(), // Auto-gen
        credential = cred,
        metadata = credMetadata,
    )
}

fun filterIssuerSigned(
    issuerSigned: ByteArray,
    requiredElements: Map<String, List<String>>
): ByteArray {
    val issuerSignedDict = cborDecode(issuerSigned) as Map<*, *>
    val ret = issuerSignedDict.toMutableMap()
    val namespaces = ret["nameSpaces"] as Map<*, *>
    val newNamespaces = mutableMapOf<String, List<CborTag>>()
    requiredElements.forEach { (namespace, requiredElements) ->
        if (namespaces.contains(namespace)) {
            val newElements = mutableListOf<CborTag>()
            requiredElements.forEach { requiredElement ->
                val elements = namespaces[namespace] as List<*>
                elements.forEach { element ->
                    if (element is CborTag) {
                        val elementDict = cborDecode(element.item as ByteArray) as Map<*, *>
                        val elementIdentifier = elementDict[ELEMENT_IDENTIFYIER] as String
                        if (elementIdentifier == requiredElement) {
                            newElements.add(element)
                        }
                    }
                }
            }
            if (newElements.size > 0) {
                newNamespaces[namespace] = newElements
            }
        }
    }
    ret["nameSpaces"] = newNamespaces
    return cborEncode(ret)
}

fun generateDeviceResponse(
    doctype: String,
    issuerSigned: ByteArray,
    devicePrivateKey: PrivateKey,
    sessionTranscript: ByteArray,
    deviceNamespaces: Map<String, Any> = emptyMap()
): ByteArray {
    val deviceNamespacesTag = CborTag(24, cborEncode(deviceNamespaces))

    val deviceAuthentication = listOf<Any>(
        "DeviceAuthentication",
        sessionTranscript,
        doctype,
        cborEncode(deviceNamespacesTag)
    )

    val deviceAuthenticationBytes = cborEncode(CborTag(24, cborEncode(deviceAuthentication)))

    val protected = cborEncode(mapOf(1 to -7))
    val sigStructure = listOf<Any>(
        "Signature1",
        protected,
        byteArrayOf(),
        deviceAuthenticationBytes
    )
    val signatureDer = Signature.getInstance("SHA256withECDSA").run {
        initSign(devicePrivateKey)
        update(cborEncode(sigStructure))
        sign()
    }

    val signature = convertDerToRaw(signatureDer)

    val deviceSignature = listOf<Any?>(
        protected,
        emptyMap<Int, Int>(),
        null,
        signature
    )

    val deviceSigned = mapOf(
        "nameSpaces" to deviceNamespacesTag,
        "deviceAuth" to mapOf("deviceSignature" to deviceSignature)
    )
    val document = mapOf(
        "docType" to doctype,
        "issuerSigned" to cborDecode(issuerSigned),
        "deviceSigned" to deviceSigned
    )
    val deviceResponse = mapOf(
        "version" to "1.0",
        "documents" to listOf(document),
        "status" to 0
    )
    return cborEncode(deviceResponse)
}

fun convertDerToRaw(signature: ByteArray): ByteArray {
    val ret = ByteArray(64)

    var rOffset = 4
    if ((signature[1].toInt() and 0x80) != 0) {
        rOffset += signature[1].toInt() and 0x7f
    }

    var rLen = signature[rOffset - 1].toInt() and 0xFF
    var rPad = 0

    if (rLen > 32) {
        rOffset += (rLen - 32)
        rLen = 32
    } else {
        rPad = 32 - rLen
    }
    signature.copyInto(ret, rPad, rOffset, rOffset + rLen)

    var sOffset = rOffset + rLen + 2
    var sLen = signature[sOffset - 1].toInt() and 0xFF
    var sPad = 0

    if (sLen > 32) {
        sOffset += (sLen - 32)
        sLen = 32
    } else {
        sPad = 32 - sLen
    }
    signature.copyInto(ret, 32 + sPad, sOffset, sOffset + sLen)

    return ret
}

internal const val ELEMENT_IDENTIFYIER = "elementIdentifier"
internal const val ELEMENT_VALUE = "elementValue"