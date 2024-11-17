package com.credman.cmwallet

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec

fun loadECPrivateKey(keyDer: ByteArray): PrivateKey {
    val devicePrivateKeySpec = PKCS8EncodedKeySpec(keyDer)
    val kf = KeyFactory.getInstance("EC")
    return kf.generatePrivate(devicePrivateKeySpec)!!
}