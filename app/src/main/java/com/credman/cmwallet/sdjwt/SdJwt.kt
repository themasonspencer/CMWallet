package com.credman.cmwallet.sdjwt

import com.credman.cmwallet.decodeBase64
import com.credman.cmwallet.decodeBase64UrlNoPadding
import com.credman.cmwallet.toBase64UrlNoPadding
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import android.util.Base64
import com.credman.cmwallet.createJWTES256
import com.credman.cmwallet.jwsDeserialization
import com.credman.cmwallet.loadECPrivateKey
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.time.Instant

class SdJwt(
    credential: String,
    holderPrivateKey: String
) {
    val issuerJwt: String
    val disclosures: List<String>
    val holderKey: PrivateKey
    init {
        val composition = credential.split('~')
        issuerJwt = composition[0]
        disclosures =
            if (composition.size <= 1) emptyList()
            else composition.subList(1, composition.size - 1)
        holderKey = loadECPrivateKey(holderPrivateKey.decodeBase64UrlNoPadding())
    }

    val verifiedResult: VerificationResult by lazy {
        verify(issuerJwt, disclosures)
    }

    fun present(
        claims: JSONArray?, // If null, match all
        nonce: String,
        clientId: String
    ): String {
        val sdJwtComponents = mutableListOf(issuerJwt)
        sdJwtComponents.addAll(if (claims == null) {
            disclosures
        } else {
            val ret = mutableListOf<String>()
            for (claimIdx in 0 until claims.length()) {
                val claim = claims.getJSONObject(claimIdx)!!
                val path = claim.getJSONArray("path")
                var sd = verifiedResult.sdMap
                for (pathIdx in 0..< path.length()) {
                    // TODO: handle path variants (null)
                    sd = sd.getJSONObject(path.getString(pathIdx))
                }
                val digest = sd.getString("_sd")
                ret.add(verifiedResult.digestDisclosureMap[digest]!!)
            }
            ret
        })
        val sdJwt = sdJwtComponents.joinToString("~", postfix="~")

        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(sdJwt.encodeToByteArray()).toBase64UrlNoPadding()
        val kbHeader = buildJsonObject {
            put("typ", "kb+jwt")
            put("alg", "ES256")
        }
        val kbPayload = buildJsonObject {
            put("iat", Instant.now().epochSecond)
            put("aud", clientId)
            put("nonce", nonce)
            put("sd_hash", digest)
        }
        val kbJwt = createJWTES256(kbHeader, kbPayload, holderKey)
        return sdJwt + kbJwt
    }
}

class VerificationResult(
    val processedJwt: JSONObject,
    val digestDisclosureMap: Map<String, String>, // Digest to encoded disclosure
    val sdMap: JSONObject,
)

fun verify(issuerJwtSerialization: String, disclosures: List<String>): VerificationResult {
    val issuerJwt = Jwt(issuerJwtSerialization)

    if (issuerJwt.payload.has("_sd_alg")) {
        assert(issuerJwt.payload["_sd_alg"] == "sha-256") {"Only support sha-256"}
    }

    val digestDisclosureMap = mutableMapOf<String, JSONArray>()
    val finalDigestDisclosureMap = mutableMapOf<String, String>()
    for (disclosure in disclosures) {
        val decoded = disclosure.decodeBase64UrlNoPadding().decodeToString()
        val disclosureJson = JSONArray(decoded)
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(disclosure.encodeToByteArray()).toBase64UrlNoPadding()
        digestDisclosureMap[digest] = disclosureJson
        finalDigestDisclosureMap[digest] = disclosure
    }
    val sdMap = JSONObject() // TODO: handle array elements
    val processedJwt = verifyInternal(issuerJwt.payload, digestDisclosureMap, mutableSetOf(), sdMap) as JSONObject
    assert(digestDisclosureMap.isEmpty()) { "All disclosures must be referenced in the issuer jwt" }
    processedJwt.remove("_sd_alg")
    return VerificationResult(processedJwt, finalDigestDisclosureMap, sdMap)
}

private fun verifyInternal(
    input: Any,
    digestDisclosureMap: MutableMap<String, JSONArray>,
    seenDigest: MutableSet<String>,
    sdMap: JSONObject
): Any {
    when (input) {
        is JSONObject -> {
            val processed = JSONObject()
            for (k in input.keys()) {
                val v = input.get(k)
                if (k == "_sd") {
                    val sdDigests = v as JSONArray
                    for (i in 0..<sdDigests.length()) {
                        val digest = sdDigests[i] as String
                        assert(!seenDigest.contains(digest)) { "Digest seen more than once: $digest" }
                        seenDigest.add(digest)
                        val disclosure = digestDisclosureMap.remove(digest)
                        if (disclosure != null) {
                            assert(disclosure.length() == 3) { "Validation failed: Invalid disclosure length. expected: 3" }
                            val claimName = disclosure[1] as String
                            assert(claimName != "_sd") { "Validation failed: claim name cannot be _sd"}
                            assert(claimName != "...") { "Validation failed: claim name cannot be ..."}
                            assert(!input.has(claimName)) { "Validation failed: claim name $claimName already exists"}
                            val claimValue = disclosure[2]
                            val childJson = JSONObject()
                            childJson.put("_sd", digest)
                            sdMap.put(claimName, childJson)
                            processed.put(claimName, verifyInternal(claimValue, digestDisclosureMap, seenDigest, childJson))
                        }
                    }
                } else {
                    val childJson = JSONObject()
                    sdMap.put(k, childJson)
                    processed.put(k, verifyInternal(v, digestDisclosureMap, seenDigest, childJson))
                }
            }
            return processed
        }
        is JSONArray -> {
            val processed = JSONArray()
            for (i in 0..<input.length()) {
                val arrElement = input[i]
                if (arrElement is JSONObject && arrElement.length() == 1 && arrElement.has("...")) {
                    val digest = arrElement["..."] as String
                    assert(!seenDigest.contains(digest)) { "Digest seen more than once: $digest" }
                    seenDigest.add(digest)
                    val disclosure = digestDisclosureMap.remove(digest)
                    if (disclosure != null) {
                        assert(disclosure.length() == 2) { "Validatiodn failed: Invalid disclosure length. expected: 2" }
                        val claimValue = disclosure[1]
                        processed.put(verifyInternal(claimValue, digestDisclosureMap, seenDigest, sdMap))
                    }
                } else {
                    processed.put(verifyInternal(arrElement, digestDisclosureMap, seenDigest, sdMap))
                }
            }
            return processed
        }
        else -> return input
    }
}

class Jwt {
    var header: JSONObject = JSONObject()
    var payload: JSONObject = JSONObject()
    private lateinit var signature: ByteArray
    private var sourceCompactSerialization: String? = null

    constructor(compactSerialization: String) {
        sourceCompactSerialization = compactSerialization
        val components = compactSerialization.split('.')
        header = JSONObject(String(components[0].decodeBase64UrlNoPadding()))
        payload = JSONObject(String(components[1].decodeBase64UrlNoPadding()))
        signature = jwsSignatureToDer(components[2], 256)

        validateIssuerJwt()
    }

    fun validateIssuerJwt() {
        require(header["typ"] == "dc+sd-jwt")
        require(header["alg"] == "ES256") { "Unsupported agl ${header["alg"]}" }
        require(payload.has("iss"))
        require(payload.has("iat"))
        require(payload.has("cnf"))
        require(payload.has("vct"))

        jwsDeserialization(sourceCompactSerialization!!)

        // TODO: The iss value MUST be an URL with a FQDN matching a dNSName Subject Alternative Name
        // (SAN) [RFC5280] entry in the leaf certificate.
    }
}

fun jwsSignatureToDer(jwsSignature: String, keySizeInBits: Int): ByteArray {
    val decodedSignature = Base64.decode(jwsSignature, Base64.URL_SAFE)
    val componentLength = keySizeInBits / 8

    if (decodedSignature.size != componentLength * 2) {
        throw IllegalArgumentException("Invalid signature length")
    }

    val r = decodedSignature.copyOfRange(0, componentLength)
    val s = decodedSignature.copyOfRange(componentLength, componentLength * 2)

    val rBigInt = BigInteger(1, r)
    val sBigInt = BigInteger(1, s)

    val derStream = ByteArrayOutputStream()
    derStream.write(0x30) // SEQUENCE tag

    val sequenceContent = ByteArrayOutputStream()
    encodeInteger(sequenceContent, rBigInt)
    encodeInteger(sequenceContent, sBigInt)

    val sequenceBytes = sequenceContent.toByteArray()
    derStream.write(encodeLength(sequenceBytes.size))
    derStream.write(sequenceBytes)

    return derStream.toByteArray()
}

private fun encodeInteger(stream: ByteArrayOutputStream, value: BigInteger) {
    val valueBytes = value.toByteArray()
    stream.write(0x02) // INTEGER tag
    stream.write(encodeLength(valueBytes.size))
    stream.write(valueBytes)
}

private fun encodeLength(length: Int): ByteArray {
    return if (length < 128) {
        byteArrayOf(length.toByte())
    } else {
        val lengthBytes = (Math.log(length.toDouble()) / Math.log(256.0)).toInt() + 1
        val buffer = ByteBuffer.allocate(lengthBytes + 1)
        buffer.put((0x80 or lengthBytes).toByte())
        for (i in lengthBytes - 1 downTo 0) {
            buffer.put((length shr (8 * i)).toByte())
        }
        buffer.array()
    }
}