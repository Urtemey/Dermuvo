using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Runtime;
internal static class VerifiedNativeFixtures
{
    internal static void Write(string root, string native)
    {
        string directory = Path.Combine(root, "verified-native"), release = Path.Combine(directory, "release");
        if (Directory.Exists(directory)) throw new IOException("Verified native fixtures must be new.");
        Directory.CreateDirectory(release);
        string name = Path.GetFileName(native);
        File.Copy(native, Path.Combine(release, name));
        byte[] key = RandomNumberGenerator.GetBytes(32);
        using var encryption = new VmEncryptionKey(key);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        try {
            Protector.Protect(typeof(Durevo.Fixture.Cases).Assembly.Location, Path.Combine(release, "protected.dll"),
                ["System.Int32 Durevo.Fixture.Cases::Arithmetic(System.Int32,System.Int32)",
                 "System.Int32 Durevo.Fixture.StringCases::TextLength(System.String)"],
                virtualize: true, native: true, encryption: encryption, verifiedNative: true);
            File.WriteAllBytes(Path.Combine(release, ReleaseInventory.ManifestName), ReleaseSigner.Create(release, "JuniorCoder-VerifiedProbe", 1, signer));
            byte[] license = LicenseIssuer.Issue(signer, new LicenseClaims("verified-player", "JuniorCoder-VerifiedProbe", "device", 1000000, 2000000, 3, 1));
            File.WriteAllBytes(Path.Combine(directory, "license.bin"), license);
            File.WriteAllBytes(Path.Combine(directory, "grant.bin"), ProgramKeyGrantIssuer.Issue(signer, license, key, 2));
            File.WriteAllBytes(Path.Combine(directory, "public.bin"), LicenseIssuer.ExportPublicKey(signer));
            File.WriteAllBytes(Path.Combine(directory, "synthetic-key.bin"), key);
            File.WriteAllText(Path.Combine(directory, "native.txt"), name);
        } finally { CryptographicOperations.ZeroMemory(key); }
    }
}
