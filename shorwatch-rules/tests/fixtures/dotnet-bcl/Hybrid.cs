using System.Security.Cryptography;

namespace Acme.Payments;

/// <summary>Classical and post-quantum signatures side by side.</summary>
public class Hybrid
{
    public void Sign(byte[] data)
    {
        // A classical key next to a post-quantum one: a transition, not a gap.
        using var rsa = RSA.Create(3072);
        using var mldsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    }
}
