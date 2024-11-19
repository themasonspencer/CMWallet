package com.credman.cmwallet.mdoc

import com.credman.cmwallet.cbor.CborTag
import com.credman.cmwallet.cbor.cborDecode
import com.credman.cmwallet.cbor.cborEncode
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
                        val elementIdentifier = elementDict["elementIdentifier"] as String
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
    sessionTranscript: ByteArray
): ByteArray {
    val deviceNamespaces = emptyMap<String, Any>()
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