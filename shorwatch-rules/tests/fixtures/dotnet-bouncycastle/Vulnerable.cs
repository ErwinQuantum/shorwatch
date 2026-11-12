using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Acme.Pki;

public class Vulnerable
{
    public void Lightweight(SecureRandom random)
    {
        var rsa = new RsaKeyPairGenerator();
        var engine = new RsaEngine();
        var ec = new ECKeyPairGenerator();
        var ecdsa = new ECDsaSigner();
        var ecdh = new ECDHBasicAgreement();
        var x25519 = new X25519Agreement();
        var ed = new Ed25519Signer();
        var dsa = new DsaSigner();
        var dh = new DHBasicAgreement();
        var triple = new DesEdeEngine();
        var sha1 = new Sha1Digest();
    }

    public void ByName()
    {
        var generator = GeneratorUtilities.GetKeyPairGenerator("RSA");
        var signer = SignerUtilities.GetSigner("SHA256withRSA");
        var legacy = SignerUtilities.GetSigner("SHA1withECDSA");
        var cipher = CipherUtilities.GetCipher("DESede/CBC/PKCS7Padding");
        var digest = DigestUtilities.GetDigest("SHA-1");
        var agreement = AgreementUtilities.GetBasicAgreement("ECDH");
    }
}
