using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Acme.Tokens;

public class Vulnerable
{
    public SigningCredentials Rsa(RSA rsa)
    {
        var key = new RsaSecurityKey(rsa);
        return new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
    }

    public SigningCredentials Pss(SecurityKey key)
    {
        return new SigningCredentials(key, "PS384");
    }

    public SigningCredentials Curve(ECDsa ecdsa)
    {
        var key = new ECDsaSecurityKey(ecdsa);
        return new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256);
    }

    public EncryptingCredentials Wrap(SecurityKey key)
    {
        return new EncryptingCredentials(key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512);
    }

    public EncryptingCredentials Agree(SecurityKey key)
    {
        return new EncryptingCredentials(key, "ECDH-ES+A256KW", SecurityAlgorithms.Aes256CbcHmacSha512);
    }

    public bool IsRsaKey(JsonWebKey jwk) => jwk.Kty == JsonWebAlgorithmsKeyTypes.RSA;

    public bool IsEcKey(JsonWebKey jwk) => jwk.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve;
}
