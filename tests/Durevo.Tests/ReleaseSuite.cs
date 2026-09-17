using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Durevo.Core;
using Durevo.Runtime;

internal static class ReleaseSuite
{
    internal static int Run(string temporaryRoot)
    {
        int count = 0;
        string root = Path.Combine(temporaryRoot, "release");
        Directory.CreateDirectory(Path.Combine(root, "content"));
        var binary = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        File.WriteAllBytes(Path.Combine(root, "durevo_vm.dll"), binary);
        File.WriteAllText(Path.Combine(root, "content", "урок.json"), "{\"level\":1}");
        using var issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] key = LicenseIssuer.ExportPublicKey(issuer);
        byte[] manifest = ReleaseSigner.Create(root, "JuniorCoder", 42, issuer);
        void Check(bool condition, string message) { count++; if (!condition) throw new Exception(message); }
        void Reject(Action action, string message)
        {
            bool rejected = false;
            try { action(); }
            catch(Exception e) when (e is CryptographicException or InvalidDataException or ArgumentException or
                UnauthorizedAccessException or IOException) { rejected = true; }
            Check(rejected, message);
        }
        VerifiedRelease Verify(byte[]? bytes = null, byte[]? publicKey = null, string product = "JuniorCoder", ulong floor = 42) =>
            SignedRelease.Verify(root, bytes ?? manifest, publicKey ?? key, product, floor);
        Check(Verify().Files.Count == 2, "Valid inventory rejected.");
        File.WriteAllBytes(Path.Combine(root, ReleaseInventory.ManifestName), manifest);
        Check(Verify().Revision == 42, "On-disk manifest exclusion failed.");
        Reject(() => ReleaseSigner.Create(root, "JuniorCoder", 43, issuer), "Existing signature silently re-signed.");
        Reject(() => Verify(publicKey: LicenseIssuer.ExportPublicKey(other)), "Untrusted signature accepted.");
        Reject(() => Verify(product: "OtherProduct"), "Cross-product manifest accepted.");
        Reject(() => Verify(floor: 43), "Old signed revision accepted.");
        Reject(() => Verify(floor: 0), "Unspecified rollback policy accepted.");
        foreach (int position in Enumerable.Range(0, manifest.Length))
        {
            var changed = (byte[])manifest.Clone(); changed[position] ^= 1;
            Reject(() => Verify(changed), "Modified signed manifest accepted.");
        }
        Reject(() => Verify(manifest[..^1]), "Truncated signature accepted.");
        Reject(() => Verify(new byte[SignedRelease.MaximumManifestBytes + 1]), "Oversized manifest accepted.");
        string dll = Path.Combine(root, "durevo_vm.dll");
        var corrupted = (byte[])binary.Clone(); corrupted[100] ^= 1;
        File.WriteAllBytes(dll, corrupted);
        Reject(() => Verify(), "Same-size native-library modification accepted.");
        File.WriteAllBytes(dll, binary);
        File.WriteAllText(Path.Combine(root, "injected.dll"), "unexpected");
        Reject(() => Verify(), "Unexpected library accepted.");
        File.Delete(Path.Combine(root, "injected.dll"));
        File.Delete(dll);
        Reject(() => Verify(), "Missing library accepted.");
        File.WriteAllBytes(dll, binary);
        File.Move(dll, Path.Combine(root, "renamed.dll"));
        Reject(() => Verify(), "Renamed file accepted.");
        File.Move(Path.Combine(root, "renamed.dll"), dll);
        foreach(string path in new[] {"../escape", "/absolute", "C:/root", "a\\b", "a//b", "./a", "a/../b",
            "x:stream", "x.", "x ", "CON", "con.txt", "a/NUL", "COM1", "LPT²", "a\0b", "durevo.release"})
            Reject(() => new ReleaseFile(path, 1, new byte[32]), "Invalid portable path accepted.");
        Reject(() => SignedRelease.Encode("JuniorCoder", 42,
            [new ReleaseFile("A.dll", 0, new byte[32]), new ReleaseFile("a.dll", 0, new byte[32])]), "Case collision accepted.");
        Reject(() => SignedRelease.Encode("JuniorCoder", 0, ReleaseInventory.Capture(root,true)), "Zero revision accepted.");
        byte[] SignRaw(byte[] payload) => payload.Concat(issuer.SignData(payload, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)).ToArray();
        byte[] payload = manifest[..^64];
        payload[0] ^= 1;
        Reject(() => Verify(SignRaw(payload)), "Wrong signed domain accepted.");
        Reject(() => Verify(SignRaw(manifest[..^64].Concat(new byte[]{0}).ToArray())), "Signed trailing data accepted.");
        var license = LicenseIssuer.Issue(issuer, new LicenseClaims("test","JuniorCoder","device",1,2,1,1));
        Reject(() => Verify(license), "License accepted as release manifest.");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            File.WriteAllBytes(Path.Combine(root,"DUREVO_VM.DLL"), binary);
            Reject(() => Verify(), "Linux case collision accepted.");
            File.Delete(Path.Combine(root,"DUREVO_VM.DLL"));
            string outside = Path.Combine(temporaryRoot,"outside.txt");
            File.WriteAllText(outside,"Not part of the release.");
            File.Delete(dll);
            File.CreateSymbolicLink(dll,outside);
            Reject(() => Verify(), "Symlinked release file accepted.");
            File.Delete(dll); File.WriteAllBytes(dll,binary);
            string linkedRoot = Path.Combine(temporaryRoot,"linked-release");
            Directory.CreateSymbolicLink(linkedRoot,root);
            Reject(() => SignedRelease.Verify(linkedRoot,manifest,key,"JuniorCoder",42), "Symlinked root accepted.");
            Directory.Delete(linkedRoot);
        }
        Check(Verify().Files.Count == 2, "Restored inventory rejected.");
        Console.WriteLine($"Release suite: {count} signature/filesystem checks passed.");
        return count;
    }
}
