using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;

namespace Acme.Pki;

public class Clean
{
    public void Symmetric()
    {
        var aes = new AesEngine();
        var sha = new Sha256Digest();
        var digest = DigestUtilities.GetDigest("SHA-256");
        var cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
        var signer = new SecureRandom();
    }
}
