#nullable disable
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using Durevo.Runtime;
internal static class VerifiedNativeProbe
{
    internal static void Run(string root)
    {
        string directory = Path.Combine(root, "verified-native");
        if (!Directory.Exists(directory)) return;
        string releaseRoot = Path.Combine(directory, "release");
        byte[] publicKey = File.ReadAllBytes(Path.Combine(directory, "public.bin"));
        var release = SignedRelease.Verify(releaseRoot, File.ReadAllBytes(Path.Combine(releaseRoot, ReleaseInventory.ManifestName)),
            publicKey, "JuniorCoder-VerifiedProbe", 1);
        string name = File.ReadAllText(Path.Combine(directory, "native.txt"));
        var image = VerifiedNativeImage.Capture(release, releaseRoot, name);
        File.Delete(Path.Combine(releaseRoot, name));
        using (var backend = image.Load())
        {
            var assembly = Assembly.Load(File.ReadAllBytes(Path.Combine(releaseRoot, "protected.dll")));
            var arithmetic = assembly.GetType("Durevo.Fixture.Cases").GetMethod("Arithmetic");
            var length = assembly.GetType("Durevo.Fixture.StringCases").GetMethod("TextLength");
            Action rejected = () => {
                try { arithmetic.Invoke(null, new object[] { 7, 3 }); }
                catch (TargetInvocationException error) when (error.InnerException is UnauthorizedAccessException) { return; }
                throw new Exception("Verified native wrapper unexpectedly executed.");
            };
            byte[] key = File.ReadAllBytes(Path.Combine(directory, "synthetic-key.bin"));
            try {
                rejected();
                using (EncryptedIntegerMachine.RegisterNativeKey(key)) rejected();
                long now = 1500000;
                using (var lease = ProgramKeyGrant.ActivateVerifiedNative(File.ReadAllBytes(Path.Combine(directory, "grant.bin")),
                    File.ReadAllBytes(Path.Combine(directory, "license.bin")), key, publicKey, EncryptedIntegerMachine.IdentifyKey(key),
                    "JuniorCoder-VerifiedProbe", "device", 0, 1, () => DateTimeOffset.FromUnixTimeSeconds(now), backend))
                {
                    backend.Dispose(); // The key retains its concrete module.
                    if (!Equals(arithmetic.Invoke(null, new object[] { 7, 3 }), unchecked((7 * 7919 + 3) ^ -123456789)))
                        throw new Exception("Verified native arithmetic mismatch.");
                    if (!Equals(length.Invoke(null, new object[] { "😀\0я" }), 4))
                        throw new Exception("Verified native string mismatch.");
                    now = 2000000; rejected();
                    now = 1500000; rejected();
                }
            } finally { Array.Clear(key, 0, key.Length); }
        }
        Console.WriteLine("PASS: verified native snapshot binding; compiled scalar/string calls, no legacy lease fallback and license expiry.");
    }
}
