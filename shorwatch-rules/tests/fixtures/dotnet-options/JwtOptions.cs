namespace Acme.Auth;

// Bound to the "Jwt" section in Program.cs, through the constant below.
public class JwtOptions
{
    public const string SectionName = "Jwt";

    public string Algorithm { get; set; } = "HS256";
    public string Issuer { get; set; } = "";
}

// Bound with `Get<SigningOptions>()`: no default, the configuration decides.
public class SigningOptions
{
    public string Algorithm { get; set; }
}

public class LegacyOptions
{
    public string Algorithm { get; set; }
}

// Nothing binds this one: the "Unbound" section of appsettings.json is not
// for it, so its default is what it holds.
public class UnboundOptions
{
    public string Algorithm { get; set; } = "HS256";
}

public class SafeOptions
{
    public string Algorithm { get; set; }
}
