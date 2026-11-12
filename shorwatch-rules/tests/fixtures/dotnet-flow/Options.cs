namespace Acme.Billing;

/// <summary>Settings read by other classes: properties, constants, a method.</summary>
public class HashOptions
{
    public const string LegacyName = "SHA1";

    public string Algorithm { get; set; } = "SHA1";

    public string Safe { get; } = "SHA256";

    public int KeyBits => 128;

    public static string Default() => "SHA1";
}

/// <summary>A class with a primary constructor (C# 12).</summary>
public class Hasher(string name)
{
    public string Name { get; } = name;

    public byte[] Hash(byte[] data)
    {
        using var algorithm = System.Security.Cryptography.HashAlgorithm.Create(name);
        return algorithm!.ComputeHash(data);
    }
}

/// <summary>A record: its components are read as properties.</summary>
public record Policy(string Digest, int Bits);

/// <summary>Only ever built with strong values.</summary>
public record SafePolicy(string Digest, int Bits);
