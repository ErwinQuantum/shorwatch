using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Acme.Auth;

public class TokenService
{
    private readonly IOptions<JwtOptions> _options;

    public TokenService(IOptions<JwtOptions> options)
    {
        _options = options;
    }

    // `Jwt:Algorithm` is RS256 in appsettings.json.
    public SigningCredentials ViaOptions(SecurityKey key)
    {
        return new SigningCredentials(key, _options.Value.Algorithm);
    }
}

public class DirectBinding
{
    // `GetSection("Signing").Get<SigningOptions>()`: ES256.
    public SigningCredentials ViaGet(IConfiguration config, SecurityKey key)
    {
        var options = config.GetSection("Signing").Get<SigningOptions>();
        return new SigningCredentials(key, options.Algorithm);
    }

    // `GetSection("Legacy").Bind(legacy)`: RS384.
    public SigningCredentials ViaBind(IConfiguration config, SecurityKey key)
    {
        var legacy = new LegacyOptions();
        config.GetSection("Legacy").Bind(legacy);
        return new SigningCredentials(key, legacy.Algorithm);
    }
}
