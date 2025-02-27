package com.credman.cmwallet.openid4vp

import org.json.JSONArray

abstract class OpenId4VPMatchedClaims

data class OpenId4VPMatchedSdJwtClaims(
    val claims: JSONArray? = null, // If null, match all claims.
) : OpenId4VPMatchedClaims()


data class OpenId4VPMatchedMDocClaims(
    val claims: Map<String, List<String>>
) : OpenId4VPMatchedClaims()

data class OpenId4VPMatchedCredential(
    val dcqlId: String,
    val matchedClaims: OpenId4VPMatchedClaims
)
