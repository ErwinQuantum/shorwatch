import java.security.MessageDigest;

/** SHA-1: collisions are practical today. Migrate to SHA-256 or SHA3-256. */
class Sha1 {
    byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data);
    }
}
