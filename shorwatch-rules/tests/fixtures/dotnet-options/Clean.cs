using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Acme.Auth;

public class Clean
{
    private readonly IOptionsSnapshot<SafeOptions> _safe;
    private readonly UnboundOptions _unbound = new();

    public Clean(IOptionsSnapshot<SafeOptions> safe)
    {
        _safe = safe;
    }

    // HS256 in appsettings.json.
    public SigningCredentials Safe(SecurityKey key)
    {
        return new SigningCredentials(key, _safe.Value.Algorithm);
    }

    // Nothing binds `UnboundOptions`: the "Unbound" section is not its own,
    // and its default is HMAC.
    public SigningCredentials NotBound(SecurityKey key)
    {
        return new SigningCredentials(key, _unbound.Algorithm);
    }
}
