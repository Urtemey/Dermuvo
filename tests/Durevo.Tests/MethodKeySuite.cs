using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Fixture;
using Durevo.Runtime;
using Mono.Cecil;

internal static class MethodKeySuite
{
    private static VerifiedNativeBackend CreateBackend(string root)
    {
        string directory = Path.Combine(root, "method-keys-native-snapshot");
        Directory.CreateDirectory(directory);
        string name = OperatingSystem.IsWindows() ? "durevo_vm.dll" : "libdurevo_vm.so";
        File.Copy(Path.Combine(AppContext.BaseDirectory, name), Path.Combine(directory, name));
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] manifest = ReleaseSigner.Create(directory, "MethodKeys", 1, signer);
        var release = SignedRelease.Verify(directory, manifest, LicenseIssuer.ExportPublicKey(signer), "MethodKeys", 1);
        return VerifiedNativeImage.Capture(release, directory, name).Load();
    }
    internal static int Run(string root, bool native, bool verified = false)
    {
        int checks = 0;
        using var backend = verified ? CreateBackend(root) : null;
        void Check(bool value, string message) { checks++; if (!value) throw new Exception(message); }
        byte[] a = RandomNumberGenerator.GetBytes(32), b = RandomNumberGenerator.GetBytes(32);
        using var keyA = new VmEncryptionKey(a);
        using var keyB = new VmEncryptionKey(b);
        string input = typeof(Cases).Assembly.Location;
        string[] methods;
        using (var source = ModuleDefinition.ReadModule(input))
            methods = new[] { "Arithmetic", "Branches" }.Select(name =>
                Protector.Methods(source).Single(m => m.DeclaringType.FullName == typeof(Cases).FullName && m.Name == name).FullName).ToArray();
        var keys = new Dictionary<string, VmEncryptionKey>(StringComparer.Ordinal) { [methods[0]] = keyA, [methods[1]] = keyB };
        int invalid = 0;
        void Reject(IReadOnlyDictionary<string, VmEncryptionKey> map, bool vm = true, VmEncryptionKey? global = null)
        {
            string path = Path.Combine(root, $"bad-method-keys-{native}-{verified}-{invalid++}.dll");
            bool rejected = false;
            try { Protector.Protect(input, path, methods, virtualize: vm, encryption: global, methodKeys: map); }
            catch (ArgumentException) { rejected = true; }
            Check(rejected && !File.Exists(path), "Invalid method-key configuration published output.");
        }
        Reject(new Dictionary<string, VmEncryptionKey> { [methods[0]] = keyA });
        Reject(new Dictionary<string, VmEncryptionKey>(keys) { ["extra"] = keyA });
        Reject(new Dictionary<string, VmEncryptionKey>(keys) { [methods[1]] = null! });
        Reject(keys, vm: false);
        Reject(keys, global: keyA);
        // Exact ordinal signature matching, irrespective of the caller dictionary comparer.
        Reject(new Dictionary<string, VmEncryptionKey>(StringComparer.OrdinalIgnoreCase)
            { [methods[0].ToUpperInvariant()] = keyA, [methods[1]] = keyB });
        string output = Path.Combine(root, $"method-keys-{native}-{verified}.dll");
        Protector.Protect(input, output, methods, virtualize: true, native: native, verifiedNative: verified, methodKeys: keys);
        var load = new AssemblyLoadContext("method-keys-" + native, isCollectible: true);
        try
        {
            var type = load.LoadFromAssemblyPath(output).GetType(typeof(Cases).FullName!)!;
            object? Call(string name, params object[] values)
            {
                try { return type.GetMethod(name)!.Invoke(null, values); }
                catch (TargetInvocationException e) { return e.InnerException!.GetType(); }
            }
            IDisposable Register(byte[] bytes) => verified ? EncryptedIntegerMachine.RegisterVerifiedNativeKey(bytes, backend!) : native ? EncryptedIntegerMachine.RegisterNativeKey(bytes) : EncryptedIntegerMachine.RegisterKey(bytes);
            Check(Equals(Call("Arithmetic", 1, 2), typeof(UnauthorizedAccessException)), "Method A ran without its key.");
            using (var leaseA = Register(a))
            {
                Check(Equals(Call("Arithmetic", 1, 2), Cases.Arithmetic(1, 2)), "Method A mismatch.");
                Check(Equals(Call("Branches", 7), typeof(UnauthorizedAccessException)), "Key A unlocked B.");
                using (var leaseB = Register(b))
                {
                    foreach (int value in new[] { int.MinValue, -239, -1, 0, 1, 239, int.MaxValue })
                    {
                        Check(Equals(Call("Arithmetic", value, 17), Cases.Arithmetic(value, 17)), "A differential mismatch.");
                        Check(Equals(Call("Branches", value), Cases.Branches(value)), "B differential mismatch.");
                    }
                    leaseA.Dispose();
                    Check(Equals(Call("Arithmetic", 1, 2), typeof(UnauthorizedAccessException)), "Disposed A remained usable.");
                    Check(Equals(Call("Branches", 7), Cases.Branches(7)), "Disposing A revoked B.");
                }
            }
            Check(Equals(Call("Branches", 7), typeof(UnauthorizedAccessException)), "Disposed B remained usable.");
            // Independent signed feature grants must also have independent lifetimes.
            using var issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] publicKey = LicenseIssuer.ExportPublicKey(issuer);
            byte[] ticketA = LicenseIssuer.Issue(issuer, new LicenseClaims("feature-A", "MethodKeys", "device", 1000, 2000, 1, 1));
            byte[] ticketB = LicenseIssuer.Issue(issuer, new LicenseClaims("feature-B", "MethodKeys", "device", 1000, 3000, 2, 1));
            byte[] grantA = ProgramKeyGrantIssuer.Issue(issuer, ticketA, a, 1);
            byte[] grantB = ProgramKeyGrantIssuer.Issue(issuer, ticketB, b, 2);
            long now = 1500;
            EncryptedIntegerMachine.KeyLease Activate(byte[] grant, byte[] ticket, byte[] secret, string id) =>
                verified ? ProgramKeyGrant.ActivateVerifiedNative(grant, ticket, secret, publicKey, id, "MethodKeys", "device",
                    0, 1, () => DateTimeOffset.FromUnixTimeSeconds(now), backend!) :
                native ? ProgramKeyGrant.ActivateNative(grant, ticket, secret, publicKey, id, "MethodKeys", "device",
                    0, 1, () => DateTimeOffset.FromUnixTimeSeconds(now)) :
                ProgramKeyGrant.Activate(grant, ticket, secret, publicKey, id, "MethodKeys", "device",
                    0, 1, () => DateTimeOffset.FromUnixTimeSeconds(now));
            using (var grantedA = Activate(grantA, ticketA, a, keyA.KeyId))
            {
                Check(Equals(Call("Arithmetic", 1, 2), Cases.Arithmetic(1, 2)), "Granted A failed.");
                Check(Equals(Call("Branches", 7), typeof(UnauthorizedAccessException)), "Grant A unlocked unlicensed B.");
                bool deniedSwap = false;
                try { using var invalidLease = Activate(grantB, ticketA, b, keyB.KeyId); }
                catch (UnauthorizedAccessException) { deniedSwap = true; }
                Check(deniedSwap, "B grant accepted A's ticket.");
                using var grantedB = Activate(grantB, ticketB, b, keyB.KeyId);
                Check(Equals(Call("Branches", 7), Cases.Branches(7)), "Granted B failed.");
                now = 2000;
                Check(Equals(Call("Arithmetic", 1, 2), typeof(UnauthorizedAccessException)), "A survived its expiry.");
                Check(Equals(Call("Branches", 7), Cases.Branches(7)), "A expiry revoked valid B.");
                now = 1500;
                Check(Equals(Call("Arithmetic", 1, 2), typeof(UnauthorizedAccessException)), "Expired A resurrected on rollback.");
                Check(Equals(Call("Branches", 7), Cases.Branches(7)), "A invalidation broke B.");
                now = 3000;
                Check(Equals(Call("Branches", 7), typeof(UnauthorizedAccessException)), "B survived its expiry.");
            }
            using var module = ModuleDefinition.ReadModule(output);
            var extracted = EncryptedRecoveryProbe.Extract(Protector.Methods(module).Single(m => m.FullName == methods[1]));
            Check(extracted.KeyId == keyB.KeyId, "B wrapper uses wrong key ID.");
            byte[] envelope = Convert.FromBase64String(extracted.Envelope);
            byte[] plain = new byte[envelope.Length - 36];
            byte[] aad = EncryptedIntegerMachine.AssociatedData(extracted.KeyId, extracted.Context);
            bool failed = false;
            try
            {
                using var wrong = new AesGcm(a, 16);
                wrong.Decrypt(envelope.AsSpan(8, 12), envelope.AsSpan(20, plain.Length), envelope.AsSpan(envelope.Length - 16), plain, aad);
            }
            catch (CryptographicException) { failed = true; }
            Check(failed, "Captured A decrypted B with B's correct context.");
            using (var correct = new AesGcm(b, 16))
                correct.Decrypt(envelope.AsSpan(8, 12), envelope.AsSpan(20, plain.Length), envelope.AsSpan(envelope.Length - 16), plain, aad);
            Check(BitConverter.ToInt32(plain, 20) > 0, "Correct-key recovery control failed.");
            CryptographicOperations.ZeroMemory(plain);
            byte[] image = File.ReadAllBytes(output);
            Check(image.AsSpan().IndexOf(a) < 0 && image.AsSpan().IndexOf(b) < 0, "Raw key embedded in assembly.");
        }
        finally { load.Unload(); CryptographicOperations.ZeroMemory(a); CryptographicOperations.ZeroMemory(b); }
        Console.WriteLine($"Method key isolation ({(verified ? "verified native" : native ? "native" : "managed")}): {checks} checks passed. Both provisioned keys remain recoverable on a hostile client.");
        return checks;
    }
}
