import javax.crypto.Cipher;

/** 3DES: deprecated, small margin against Grover. Migrate to AES-256-GCM. */
class TripleDes {
    Cipher cipher() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }
}
