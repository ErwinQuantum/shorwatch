package com.example.authserver.tls;

import java.util.List;
import javax.crypto.KeyAgreement;

/** Already migrating: hybrid post-quantum key exchange preferred for TLS. */
public class HybridTlsSettings {
    static final List<String> NAMED_GROUPS = List.of("X25519MLKEM768", "x25519", "secp256r1");

    /** Classical half kept for peers that don't speak ML-KEM yet. */
    KeyAgreement fallbackAgreement() throws Exception {
        return KeyAgreement.getInstance("X25519");
    }
}
