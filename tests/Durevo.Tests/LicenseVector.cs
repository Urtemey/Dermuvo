using System.Security.Cryptography;
using System.Text.Json;
using Durevo.Core;
using Durevo.Runtime;

internal static class LicenseVector
{
    private sealed record Vector(string Description, string PublicKey, string Ticket);
    internal static void Write(string output)
    {
        if (File.Exists(output)) throw new IOException("Vector output already exists.");
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var claims = new LicenseClaims("cross-platform-test", "Durevo.TestProduct", "synthetic-test-device",
            1000000, 2000000, 1, 1);
        var data = new Vector("Synthetic Windows-issued interoperability vector; no private key retained.",
            Convert.ToBase64String(LicenseIssuer.ExportPublicKey(signer)),
            Convert.ToBase64String(LicenseIssuer.Issue(signer, claims)));
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        File.WriteAllText(output, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
    }
    internal static int Check()
    {
        var json = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "windows-license-vector.json"));
        var data = JsonSerializer.Deserialize<Vector>(json)!;
        var claims = OfflineLicense.Verify(Convert.FromBase64String(data.Ticket), Convert.FromBase64String(data.PublicKey),
            "Durevo.TestProduct", "synthetic-test-device", 1, 1, DateTimeOffset.FromUnixTimeSeconds(1500000));
        if (claims.Id != "cross-platform-test") throw new Exception("Interoperability vector mismatch.");
        return 1;
    }
}
