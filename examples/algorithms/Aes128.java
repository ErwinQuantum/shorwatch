import javax.crypto.KeyGenerator;

/** AES-128: about 64 bits against Grover. Shorwatch offers a fix: 128 -> 256. */
class Aes128 {
    Object key() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        return generator.generateKey();
    }
}
