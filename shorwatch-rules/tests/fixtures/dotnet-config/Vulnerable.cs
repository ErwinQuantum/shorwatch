using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Acme.Auth;

public class Vulnerable
{
    private readonly IConfiguration _config;

    public Vulnerable(IConfiguration config)
    {
        _config = config;
    }

    public SigningCredentials Indexer(SecurityKey key)
    {
        return new SigningCredentials(key, _config["Jwt:Algorithm"]);
    }

    public SigningCredentials ViaSection(SecurityKey key)
    {
        var algorithm = _config.GetSection("Jwt").GetSection("Section").GetValue<string>("Name");
        return new SigningCredentials(key, algorithm);
    }

    public SigningCredentials Default(SecurityKey key)
    {
        var algorithm = _config.GetValue<string>("Jwt:Missing", "PS256");
        return new SigningCredentials(key, algorithm);
    }

    public HashAlgorithm Digest()
    {
        return HashAlgorithm.Create(_config.GetSection("Crypto:Digest").Value);
    }
}
