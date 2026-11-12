using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Acme.Tokens;

public class Clean
{
    public SigningCredentials Shared(byte[] secret)
    {
        var key = new SymmetricSecurityKey(secret);
        return new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    }

    public SigningCredentials Named(SecurityKey key)
    {
        return new SigningCredentials(key, "HS512");
    }

    public EncryptingCredentials Direct(SecurityKey key)
    {
        return new EncryptingCredentials(key, SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512);
    }
}
