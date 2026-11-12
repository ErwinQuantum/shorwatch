using System.Security.Cryptography;

namespace Acme.Billing;

public class Clean
{
    public void Safe(HashOptions options)
    {
        // Settings that only ever hold strong values.
        HashAlgorithm.Create(options.Safe);
        var hasher = new Hasher("SHA512");
        var policy = new SafePolicy("SHA256", 3072);
        HashAlgorithm.Create(policy.Digest);
    }

    public void Initializers()
    {
        var aes = new AesManaged { KeySize = 256 };
        // Assigning a name that is also a variable of this method is not a setter.
        var KeySize = 128;
        var other = new Config { KeySize = 64 };
    }

    private sealed class Config
    {
        public int KeySize { get; set; }
    }
}
