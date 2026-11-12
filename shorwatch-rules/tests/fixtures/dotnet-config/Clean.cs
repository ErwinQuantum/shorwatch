using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Acme.Auth;

public class Clean
{
    private readonly IConfiguration _config;

    public Clean(IConfiguration config)
    {
        _config = config;
    }

    public SigningCredentials Shared(SecurityKey key)
    {
        return new SigningCredentials(key, _config["Safe:Algorithm"]);
    }

    public SigningCredentials Absent(SecurityKey key)
    {
        return new SigningCredentials(key, _config["Nothing:Here"]);
    }

    public string Issuer()
    {
        return _config["Jwt:Issuer"];
    }
}
