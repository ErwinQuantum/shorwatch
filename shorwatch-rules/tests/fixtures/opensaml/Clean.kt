package com.example.sso

import org.opensaml.xmlsec.encryption.support.EncryptionConstants
import org.opensaml.xmlsec.signature.support.SignatureConstants

class Clean {
    fun symmetric(): Array<String> = arrayOf(
        EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM,
        SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
        SignatureConstants.ALGO_ID_DIGEST_SHA256,
    )
}
