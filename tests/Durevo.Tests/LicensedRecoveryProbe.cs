using System.Collections;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Fixture;
using Durevo.Runtime;
using Mono.Cecil;

// Adversarial regression against our synthetic fixture only.
// Assumes arbitrary managed execution in the licensed process, not a remote exploit.
internal static class LicensedRecoveryProbe
{
    internal static int Run(string root, bool native = false)
    {
        int checks = 0;
        void Check(bool value, string message) { checks++; if (!value) throw new Exception(message); }
        byte[] sourceKey = RandomNumberGenerator.GetBytes(32);
        byte[]? captured = null;
        EncryptedIntegerMachine.KeyLease? lease = null;
        var load = new AssemblyLoadContext("licensed-recovery-" + native, isCollectible: true);
        try
        {
            string output = Path.Combine(root, native ? "licensed-native-recovery.dll" : "licensed-recovery.dll");
            string input = typeof(Cases).Assembly.Location;
            using var issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            long now = 1500000;
            byte[] ticket = LicenseIssuer.Issue(issuer,
                new LicenseClaims("probe", "JuniorCoder", "synthetic-device", 1000000, 2000000, 1, 1));
            byte[] grant = ProgramKeyGrantIssuer.Issue(issuer, ticket, sourceKey, 1);
            string keyId = EncryptedIntegerMachine.IdentifyKey(sourceKey);
            using (var encryption = new VmEncryptionKey(sourceKey))
            {
                using var module = ModuleDefinition.ReadModule(input);
                var selection = Protector.Methods(module).Where(m => m.Name is "Arithmetic" or "Branches")
                    .Select(m => m.FullName).ToArray();
                Protector.Protect(input, output, selection, virtualize: true, native: native, encryption: encryption);
            }
            lease = native
                ? ProgramKeyGrant.ActivateNative(grant, ticket, sourceKey, LicenseIssuer.ExportPublicKey(issuer),
                    keyId, "JuniorCoder", "synthetic-device", 1, 1, () => DateTimeOffset.FromUnixTimeSeconds(now))
                : ProgramKeyGrant.Activate(grant, ticket, sourceKey, LicenseIssuer.ExportPublicKey(issuer),
                    keyId, "JuniorCoder", "synthetic-device", 1, 1, () => DateTimeOffset.FromUnixTimeSeconds(now));
            // Attacker routine receives only public key ID. Issuer-side raw buffer has been wiped;
            // the build-side authority above was disposed before the attack.
            CryptographicOperations.ZeroMemory(sourceKey);
            var target = load.LoadFromAssemblyPath(output).GetType(typeof(Cases).FullName!)!;
            Check((int)target.GetMethod("Arithmetic")!.Invoke(null, [3, 5])! == Cases.Arithmetic(3, 5),
                "Licensed fixture did not execute.");
            captured = CaptureLiveKey(keyId, native);
            Check(EncryptedIntegerMachine.IdentifyKey(captured) == keyId, "Live capture recovered wrong key.");

            now = 2000000;
            bool denied = false;
            try { target.GetMethod("Arithmetic")!.Invoke(null, [3, 5]); }
            catch (TargetInvocationException ex) when (ex.InnerException is UnauthorizedAccessException) { denied = true; }
            Check(denied, "Expired original wrapper remained authorized.");
            lease.Dispose();

            using var protectedModule = ModuleDefinition.ReadModule(output);
            foreach (string name in new[] { "Arithmetic", "Branches" })
            {
                var extracted = EncryptedRecoveryProbe.Extract(Protector.Methods(protectedModule).Single(m => m.Name == name));
                byte[] envelope = Convert.FromBase64String(extracted.Envelope);
                byte[] plain = new byte[envelope.Length - 36];
                int[]? words = null;
                try
                {
                    using var aes = new AesGcm(captured, 16);
                    aes.Decrypt(envelope.AsSpan(8, 12), envelope.AsSpan(20, plain.Length),
                        envelope.AsSpan(envelope.Length - 16), plain,
                        EncryptedIntegerMachine.AssociatedData(extracted.KeyId, extracted.Context));
                    using var reader = new BinaryReader(new MemoryStream(plain, false));
                    Check(reader.ReadInt32() == (native ? 1 : 0), "Unexpected backend.");
                    int locals = reader.ReadInt32(), stack = reader.ReadInt32(), argCount = reader.ReadInt32();
                    int xor = reader.ReadInt32(), count = reader.ReadInt32();
                    Check(count > 0 && count <= EncryptedIntegerMachine.MaximumWords &&
                        plain.Length == 24 + count * 4, "Invalid recovered program.");
                    words = Enumerable.Range(0, count).Select(_ => reader.ReadInt32()).ToArray();
                    foreach (int x in new[] { -239, -1, 0, 1, 239, int.MinValue, int.MaxValue })
                    {
                        int[] arguments = argCount == 2 ? [x, unchecked(x * 17)] : [x];
                        int expected = name == "Arithmetic" ? Cases.Arithmetic(arguments[0], arguments[1]) : Cases.Branches(x);
                        // No license or key registration involved: execute the recovered program directly.
                        Check(IntegerMachine.Run(words, arguments, locals, stack, xor) == expected,
                            "Recovered method mismatch: " + name);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plain);
                    if (words != null) Array.Clear(words);
                }
            }
            Console.WriteLine("KNOWN GAP: " + (native ? "native handle memory read" : "managed reflection") + " recovered a licensed VM key; two recovered methods execute after license expiry without activation.");
            return checks;
        }
        finally
        {
            lease?.Dispose();
            CryptographicOperations.ZeroMemory(sourceKey);
            if (captured != null) CryptographicOperations.ZeroMemory(captured);
            load.Unload();
        }
    }

    private static byte[] CaptureLiveKey(string keyId, bool native)
    {
        // Deliberately outside normal API: demonstrates the current managed-memory boundary.
        var registry = (IDictionary)typeof(EncryptedIntegerMachine)
            .GetField("Keys", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;
        var entry = registry[keyId] ?? throw new InvalidOperationException("No active key.");
        if (native)
        {
            // This targets only our live synthetic handle. No arbitrary process/memory scanning.
            var handle = (SafeHandle)entry.GetType().GetProperty("NativeHandle", BindingFlags.NonPublic | BindingFlags.Instance)!
                .GetValue(entry)!;
            bool held = false;
            try
            {
                handle.DangerousAddRef(ref held);
                byte[] captured = new byte[32];
                Marshal.Copy(handle.DangerousGetHandle(), captured, 0, captured.Length);
                return captured;
            }
            finally { if (held) handle.DangerousRelease(); }
        }
        return (byte[])((byte[])entry.GetType().GetProperty("Bytes", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(entry)!).Clone();
    }
}
