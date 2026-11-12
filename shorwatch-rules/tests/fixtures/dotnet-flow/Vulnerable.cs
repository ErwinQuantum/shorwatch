using System.Security.Cryptography;

namespace Acme.Billing;

public class Vulnerable
{
    private readonly HashOptions _options = new();

    public void Properties()
    {
        var options = new HashOptions();
        // A property with an initializer, read through a variable of its type.
        HashAlgorithm.Create(options.Algorithm);
        // A constant of another class, and a method of another class.
        HashAlgorithm.Create(HashOptions.LegacyName);
        HashAlgorithm.Create(HashOptions.Default());
        // A field of this class, typed.
        HashAlgorithm.Create(_options.Algorithm);
    }

    public void Constructors()
    {
        // The argument reaches the primary constructor's parameter.
        var hasher = new Hasher("SHA1");
        var policy = new Policy("SHA1", 1024);
        HashAlgorithm.Create(policy.Digest);
    }

    public void ObjectInitializers()
    {
        // Properties set while constructing are setter calls.
        var aes = new AesManaged { KeySize = 128 };
        var csp = new AesCryptoServiceProvider { KeySize = 128, Padding = PaddingMode.PKCS7 };
        var rsa = new RSACryptoServiceProvider { PersistKeyInCsp = false };
    }

    public void Choices(bool legacy, string tier)
    {
        var name = legacy ? "SHA1" : "SHA256";
        HashAlgorithm.Create(name);
        HashAlgorithm.Create(tier switch { "old" => "SHA1", _ => "SHA512" });
    }
}
