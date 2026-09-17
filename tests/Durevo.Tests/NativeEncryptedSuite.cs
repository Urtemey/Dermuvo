using System.Reflection;
using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Runtime;

internal static class NativeEncryptedSuite
{
    internal static int Run()
    {
        int checks = 0;
        void Check(bool ok, string message) { checks++; if (!ok) throw new Exception(message); }
        void Reject(Action action, string message)
        {
            bool rejected = false;
            try { action(); }
            catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidDataException or CryptographicException)
            { rejected = true; }
            Check(rejected, message);
        }
        byte[] key = RandomNumberGenerator.GetBytes(32);
        using var issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        long now = 1500000;
        const string context = "native-owned-program";
        using var encryption = new VmEncryptionKey(key);
        int[] code = [(int)IntegerMachine.Operation.Constant, 73, (int)IntegerMachine.Operation.Return, 0];
        const int mask = 17;
        for (int i = 0; i < code.Length; i++) code[i] ^= unchecked(mask + i * (int)0x9e3779b9);
        string envelope = encryption.Seal(code, 0, 1, 0, mask, true, context);
        byte[] license = LicenseIssuer.Issue(issuer,
            new LicenseClaims("native-lease", "JuniorCoder", "synthetic-native", 1000000, 2000000, 3, 1));
        byte[] grant = ProgramKeyGrantIssuer.Issue(issuer, license, key, 2);
        EncryptedIntegerMachine.KeyLease Activate() => ProgramKeyGrant.ActivateNative(grant, license, key,
            LicenseIssuer.ExportPublicKey(issuer), encryption.KeyId, "JuniorCoder", "synthetic-native", 0, 1,
            () => DateTimeOffset.FromUnixTimeSeconds(now));
        int Run() => EncryptedIntegerMachine.RunNative(envelope, encryption.KeyId, context, []);
        try
        {
            using (EncryptedIntegerMachine.RegisterKey(key))
                Reject(() => Run(), "Native-only entry fell back to managed decryption.");
            byte[] modified = (byte[])grant.Clone(); modified[80] ^= 1;
            Reject(() => ProgramKeyGrant.ActivateNative(modified, license, key, LicenseIssuer.ExportPublicKey(issuer),
                encryption.KeyId, "JuniorCoder", "synthetic-native", 0, 1, () => DateTimeOffset.FromUnixTimeSeconds(now)),
                "Native activation accepted a forged grant.");
            using (var lease = Activate())
            {
                var retained = (byte[])lease.GetType().GetProperty("Bytes", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .GetValue(lease)!;
                Check(retained.Length == 0, "Native lease retains a managed key buffer.");
                Check(Run() == 73, "Signed native execution mismatch.");
                string managedEnvelope = encryption.Seal(code, 0, 1, 0, mask, false, context);
                Reject(() => EncryptedIntegerMachine.RunNative(managedEnvelope, encryption.KeyId, context, []),
                    "Native entry accepted a managed backend marker.");
                int[] invalid = [(999 ^ mask), unchecked(0 ^ (mask + (int)0x9e3779b9))];
                Reject(() => EncryptedIntegerMachine.RunNative(encryption.Seal(invalid, 0, 1, 0, mask, true, context),
                    encryption.KeyId, context, []), "Authenticated invalid opcode executed.");
                now = 2000000;
                Reject(() => Run(), "Native license expiry ignored.");
                now = 1500000;
                Reject(() => Run(), "Revoked native lease resurrected on rollback.");
            }
            using (var lease = EncryptedIntegerMachine.RegisterNativeKey(key))
            {
                var tasks = Enumerable.Range(0, 64).Select(_ => Task.Run(() =>
                {
                    try { return Run() == 73; }
                    catch (UnauthorizedAccessException) { return true; }
                })).ToArray();
                lease.Dispose();
                Task.WaitAll(tasks);
                foreach (var task in tasks) Check(task.Result, "Concurrent native execution returned corrupt result.");
            }
            Reject(() => Run(), "Disposed native key remains available.");
            // Caller owns its provisioning buffer. Mutating it after import must not affect the native key.
            byte[] supplied = (byte[])key.Clone();
            using (EncryptedIntegerMachine.RegisterNativeKey(supplied))
            {
                CryptographicOperations.ZeroMemory(supplied);
                Check(Run() == 73, "Native key import borrowed caller memory.");
            }
            Console.WriteLine($"Native encrypted ownership/lifecycle suite: {checks} checks passed.");
            return checks;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
