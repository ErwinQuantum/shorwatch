using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using R = System.Security.Cryptography.RSA;

namespace Acme.Payments;

/// <summary>Signing and hashing with the base class library.</summary>
public class Vulnerable
{
    private const string LegacyHash = "SHA1";
    private RSA _signingKey = RSA.Create(2048);

    public byte[] Sign(byte[] data)
    {
        using var rsa = RSA.Create(3072);
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public byte[] Encrypt(RSA key, byte[] data)
    {
        return key.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    public void Curves(X509Certificate2 cert)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ecdh = ECDiffieHellman.Create();
        var viaCert = cert.GetRSAPrivateKey();
        var viaAlias = R.Create();
        ECDsa target = new();
    }

    public void Legacy(byte[] data)
    {
        var dsa = new DSACryptoServiceProvider(1024);
        var old = new RSACryptoServiceProvider(1024);
        var triple = TripleDES.Create();
        var sha = SHA1.Create();
        var viaName = HashAlgorithm.Create(LegacyHash);
        var digest = SHA1.HashData(data);
        var request = HashAlgorithmName.SHA1;
        var named = CryptoConfig.CreateFromName("RSA");
    }

    public void Weak(byte[] data)
    {
        Aes aes = Aes.Create();
        aes.KeySize = 128;
        var managed = new AesManaged();
        managed.KeySize = 128;
    }
}
