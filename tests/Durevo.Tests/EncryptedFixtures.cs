using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Fixture;
using Mono.Cecil;

internal static class EncryptedFixtures
{
    internal static void Write(string output, string? gameAssembly = null)
    {
        string release = Path.Combine(output, "encrypted-release");
        if (Directory.Exists(release)) throw new IOException("Encrypted fixture must be new.");
        Directory.CreateDirectory(release);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var encryption = new VmEncryptionKey(key);
            string input = typeof(Cases).Assembly.Location;
            string[] selection;
            using (var module = ModuleDefinition.ReadModule(input))
                selection = Protector.Methods(module).Where(m => m.Name is "Arithmetic" or "Branches")
                    .Select(m => m.FullName).ToArray();
            Protector.Protect(input, Path.Combine(release,"Durevo.Fixture.dll"), selection, virtualize:true, encryption:encryption);
            string nativeRelease = Path.Combine(output, "encrypted-native-release");
            Directory.CreateDirectory(nativeRelease);
            Protector.Protect(input, Path.Combine(nativeRelease, "Durevo.Fixture.dll"), selection,
                virtualize:true, native:true, encryption:encryption);
            if (gameAssembly != null)
            {
                string signature = "System.Boolean JuniorCoder.Scripts.Game.LogicLua.PythonCodeHandlerBeforeLaunch::HasMultipleTopLevelArguments(System.String)";
                string snapshot = Path.Combine(output, "game-string-original.dll");
                File.Copy(gameAssembly, snapshot, false);
                var managedReport = Protector.Protect(snapshot, Path.Combine(output, "game-string-managed.dll"),
                    [signature], virtualize:true, encryption:encryption);
                var nativeReport = Protector.Protect(snapshot, Path.Combine(output, "game-string-native.dll"),
                    [signature], virtualize:true, native:true, encryption:encryption);
                File.WriteAllText(Path.Combine(output, "game-string-evidence.json"),
                    System.Text.Json.JsonSerializer.Serialize(new { Source=Path.GetFullPath(gameAssembly), Method=signature,
                        Managed=managedReport, Native=nativeReport }, new System.Text.Json.JsonSerializerOptions { WriteIndented=true }));
            }
            using var issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var license = LicenseIssuer.Issue(issuer,new Durevo.Runtime.LicenseClaims(
                "player-grant","JuniorCoder","synthetic-player",1000000,2000000,3,1));
            File.WriteAllBytes(Path.Combine(output,"program-license.bin"),license);
            File.WriteAllBytes(Path.Combine(output,"program-grant.bin"),ProgramKeyGrantIssuer.Issue(issuer,license,key,2));
            File.WriteAllBytes(Path.Combine(output,"program-public.bin"),LicenseIssuer.ExportPublicKey(issuer));
            File.WriteAllText(Path.Combine(output,"program-key-id.txt"),encryption.KeyId);
            // Synthetic activation secret deliberately separate from the distributed DLL directory.
            File.WriteAllBytes(Path.Combine(output,"synthetic-program.vmkey"),key);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
