using System.Security.Cryptography;

namespace Acme.Payments;

public class Clean
{
    public byte[] Hash(byte[] data, byte[] key)
    {
        // SHA-256, HMAC-SHA-1 and AES with a 256-bit key are not affected by
        // Shor, and HMAC does not rely on collision resistance.
        using var hmac = new HMACSHA1(key);
        var mac = hmac.ComputeHash(data);
        var digest = SHA256.HashData(data);
        Aes aes = Aes.Create();
        aes.KeySize = 256;
        var name = HashAlgorithmName.SHA256;
        return digest;
    }

    public byte[] Derive(byte[] password, byte[] salt)
    {
        // Key derivation over SHA-1 does not rely on collision resistance.
        var kdf = new Rfc2898DeriveBytes(password, salt, 600000, HashAlgorithmName.SHA1);
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, 600000, HashAlgorithmName.SHA1, 32);
    }

    public void Lookalikes(Config config)
    {
        // A property that merely shares a name with a base class library one.
        config.KeySize = 128;
    }

    private sealed class Config
    {
        public int KeySize { get; set; }
    }
}
