using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Runtime;
using O = Durevo.Runtime.IntegerMachine.Operation;

internal static class VerifiedNativeSuite
{
    internal static int Run(string native, bool poison)
    {
        int searches = 0, checks = 0;
        if (poison) NativeLibrary.SetDllImportResolver(typeof(EncryptedIntegerMachine).Assembly, (name, _, _) => {
            if (name == "durevo_vm") { searches++; throw new DllNotFoundException("Synthetic poisoned name resolver."); }
            return IntPtr.Zero;
        });
        void Check(bool condition, string message) { checks++; if (!condition) throw new Exception(message); }
        void Reject(Action action) {
            try { action(); }
            catch (Exception e) when (e is UnauthorizedAccessException or CryptographicException or InvalidDataException or ObjectDisposedException or DllNotFoundException) { checks++; return; }
            throw new Exception("Expected rejection.");
        }
        string root = Path.Combine(Path.GetTempPath(), "durevo-verified-native-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        byte[] source = File.ReadAllBytes(native);
        string imagePath = Path.Combine(root, Path.GetFileName(native));
        File.WriteAllBytes(imagePath, source);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] publicKey = LicenseIssuer.ExportPublicKey(signer);
        byte[] manifest = ReleaseSigner.Create(root, "JuniorCoder", 4, signer);
        var release = SignedRelease.Verify(root, manifest, publicKey, "JuniorCoder", 4);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] recovered = new byte[32];
        using var encryption = new VmEncryptionKey(key);
        var context = new AssemblyLoadContext("verified-native-wrapper", true);
        try
        {
            Reject(() => VerifiedNativeImage.Capture(release, root, "absent.dll"));
            byte[] tampered = source.ToArray(); tampered[^1] ^= 1; File.WriteAllBytes(imagePath, tampered);
            Reject(() => VerifiedNativeImage.Capture(release, root, Path.GetFileName(native)));
            File.WriteAllBytes(imagePath, source);
            var snapshot = VerifiedNativeImage.Capture(release, root, Path.GetFileName(native));
            File.Delete(imagePath); // Loading must consume the captured bytes, not reopen this path.
            using var backend = snapshot.Load();
            Check(backend.Product == "JuniorCoder" && backend.Revision == 4, "Backend lost signed identity.");
            const int mask = 17;
            int[] code = [(int)O.Constant, 73, (int)O.Return, 0];
            for (int i = 0; i < code.Length; i++) code[i] ^= unchecked(mask + i * (int)0x9e3779b9);
            string envelope = encryption.Seal(code, 0, 1, 0, mask, true, "verified-native");
            int Execute() => EncryptedIntegerMachine.RunVerifiedNative(envelope, encryption.KeyId, "verified-native", []);
            Reject(() => Execute());
            using (EncryptedIntegerMachine.RegisterKey(key)) Reject(() => Execute());
            if (poison) {
                Reject(() => EncryptedIntegerMachine.RegisterNativeKey(key));
                Check(searches == 1, "Poison resolver positive control was not exercised.");
            }
            else using (EncryptedIntegerMachine.RegisterNativeKey(key)) Reject(() => Execute());
            string transformed = Path.Combine(root, "wrapped.dll");
            Protector.Protect(typeof(Durevo.Fixture.Cases).Assembly.Location, transformed,
                ["System.Int32 Durevo.Fixture.Cases::Arithmetic(System.Int32,System.Int32)",
                 "System.Int32 Durevo.Fixture.StringCases::TextLength(System.String)"],
                virtualize: true, native: true, encryption: encryption, verifiedNative: true);
            var assembly = context.LoadFromAssemblyPath(transformed);
            var arithmetic = assembly.GetType("Durevo.Fixture.Cases")!.GetMethod("Arithmetic")!;
            var length = assembly.GetType("Durevo.Fixture.StringCases")!.GetMethod("TextLength")!;
            long now = 1500000;
            byte[] ticket = LicenseIssuer.Issue(signer, new LicenseClaims("verified-test", "JuniorCoder", "device", 1000000, 2000000, 3, 1));
            byte[] grant = ProgramKeyGrantIssuer.Issue(signer, ticket, key, 2);
            EncryptedIntegerMachine.KeyLease Activate() => ProgramKeyGrant.ActivateVerifiedNative(grant, ticket, key,
                publicKey, encryption.KeyId, "JuniorCoder", "device", 0, 1, () => DateTimeOffset.FromUnixTimeSeconds(now), backend);
            byte[] altered = grant.ToArray(); altered[^1] ^= 1;
            Reject(() => ProgramKeyGrant.ActivateVerifiedNative(altered, ticket, key, publicKey, encryption.KeyId,
                "JuniorCoder", "device", 0, 1, () => DateTimeOffset.FromUnixTimeSeconds(now), backend));
            using (var lease = Activate())
            {
                Check(Execute() == 73, "Verified native execution mismatch.");
                var handle = (SafeHandle)lease.GetType().GetProperty("NativeHandle", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(lease)!;
                bool retained = false;
                try { handle.DangerousAddRef(ref retained); Marshal.Copy(handle.DangerousGetHandle(), recovered, 0, recovered.Length); }
                finally { if (retained) handle.DangerousRelease(); }
                Check(recovered.SequenceEqual(key), "Known native key extraction probe changed; investigate rather than assume security.");
                foreach (int value in new[] { int.MinValue, int.MaxValue, -1, 0, 1 })
                    Check(Equals(arithmetic.Invoke(null, [value, 3]), Durevo.Fixture.Cases.Arithmetic(value, 3)), "Compiled verified wrapper changed behavior.");
                foreach (string text in new[] { "", "abc", "😀\0я", "\ud800" })
                    Check(Equals(length.Invoke(null, [text]), text.Length), "Verified string dispatch changed behavior.");
                now = 2000000; Reject(() => Execute());
                now = 1500000; Reject(() => Execute());
            }
            now = 2000000;
            using (var lease = EncryptedIntegerMachine.RegisterVerifiedNativeKey(recovered, backend))
            {
                backend.Dispose();
                Check(Execute() == 73, "Disposing factory prematurely unloaded an active lease.");
                Console.WriteLine("KNOWN GAP: verified native key remains readable in process memory; recovered key executes after license expiry via low-level provisioning.");
                byte[] otherKey = RandomNumberGenerator.GetBytes(32);
                try { Reject(() => EncryptedIntegerMachine.RegisterVerifiedNativeKey(otherKey, backend)); }
                finally { CryptographicOperations.ZeroMemory(otherKey); }
                var tasks = Enumerable.Range(0, 64).Select(_ => Task.Run(() => {
                    try { return Execute() == 73; } catch (UnauthorizedAccessException) { return true; }
                })).ToArray();
                lease.Dispose();
                Task.WaitAll(tasks);
                Check(tasks.All(t => t.Result), "Concurrent disposal produced an invalid outcome.");
            }
            Reject(() => Execute());
            if (poison) Check(searches == 1, "Verified dispatch consulted the poisoned name resolver.");
            using (var another = snapshot.Load())
            using (EncryptedIntegerMachine.RegisterVerifiedNativeKey(key, another))
                Check(Execute() == 73, "Reloading a captured image failed.");
            Console.WriteLine($"PASS: verified native binding; {checks} signed snapshot, explicit-handle, compiler, license and lifetime checks; poisoned-name-control={poison}.");
            return checks;
        }
        finally { context.Unload(); CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(recovered); }
    }
}
