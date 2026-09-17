using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Fixture;
using Durevo.Runtime;
using Mono.Cecil;

internal static class EncryptedVmSuite
{
    internal static int Run(string root, bool native)
    {
        int checks = 0;
        void Check(bool ok, string message) { checks++; if (!ok) throw new Exception(message); }
        void Reject(Action action, string message)
        {
            bool failed = false;
            try { action(); }
            catch (Exception e) when (e is UnauthorizedAccessException or CryptographicException or InvalidDataException
                or ArgumentException or InvalidOperationException or FormatException) { failed = true; }
            Check(failed, message);
        }
        byte[] key = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var authority = new VmEncryptionKey(key);
            const string context = "synthetic-vector";
            int xor = 173;
            int[] words = [(int)IntegerMachine.Operation.Argument,0,(int)IntegerMachine.Operation.Constant,7,
                (int)IntegerMachine.Operation.Mul,0,(int)IntegerMachine.Operation.Return,0];
            for (int i = 0; i < words.Length; i++) words[i] ^= unchecked(xor + i * (int)0x9e3779b9);
            string envelope = authority.Seal(words, 0, 2, 1, xor, native, context);
            Check(envelope != authority.Seal(words, 0, 2, 1, xor, native, context), "Encryption reused a nonce.");
            Reject(() => EncryptedIntegerMachine.Run(envelope, authority.KeyId, context, [3]), "Missing key allowed execution.");
            Reject(() => EncryptedIntegerMachine.AssociatedData(new string('A', 4096), context), "Oversized key identity accepted.");
            Reject(() => EncryptedIntegerMachine.AssociatedData(authority.KeyId, new string('x', 4097)), "Oversized context accepted.");
            byte[] supplied = (byte[])key.Clone();
            using (var lease = (native ? EncryptedIntegerMachine.RegisterNativeKey(supplied) : EncryptedIntegerMachine.RegisterKey(supplied)))
            {
                CryptographicOperations.ZeroMemory(supplied);
                Check(EncryptedIntegerMachine.Run(envelope, authority.KeyId, context, [3]) == 21, "External key execution mismatch.");
                Reject(() => EncryptedIntegerMachine.RegisterKey(key), "Duplicate registration accepted.");
                Reject(() => EncryptedIntegerMachine.Run(envelope, authority.KeyId, context + "-other", [3]), "Context substitution accepted.");
                Reject(() => EncryptedIntegerMachine.Run(envelope, authority.KeyId, context, []), "Wrong argument count accepted.");
                byte[] raw = Convert.FromBase64String(envelope);
                for (int i = 0; i < raw.Length; i++)
                {
                    byte[] changed = (byte[])raw.Clone(); changed[i] ^= 1;
                    Reject(() => EncryptedIntegerMachine.Run(Convert.ToBase64String(changed), authority.KeyId, context, [3]),
                        "Modified envelope accepted at " + i);
                }
                Reject(() => EncryptedIntegerMachine.Run(Convert.ToBase64String(raw[..^1]), authority.KeyId, context, [3]), "Truncation accepted.");
                using var wrong = new VmEncryptionKey(RandomNumberGenerator.GetBytes(32));
                Reject(() => EncryptedIntegerMachine.Run(wrong.Seal(words, 0, 2, 1, xor, native, context), authority.KeyId, context, [3]),
                    "Wrong encryption key accepted.");
                Reject(() => EncryptedIntegerMachine.Run(authority.Seal(words, -1, 2, 1, xor, native, context), authority.KeyId, context, [3]),
                    "Authenticated invalid metadata accepted.");
            }
            Reject(() => EncryptedIntegerMachine.Run(envelope, authority.KeyId, context, [3]), "Disposed key still available.");

            string[] names = ["Arithmetic","Branches","Divide","Checked","CheckedUnsignedAdd","CheckedUnsignedSub","CheckedUnsignedMul"];
            string input = typeof(Cases).Assembly.Location;
            string[] selection;
            using (var module = ModuleDefinition.ReadModule(input))
                selection = Protector.Methods(module).Where(m => names.Contains(m.Name)).Select(m => m.FullName).ToArray();
            string output = Path.Combine(root, native ? "encrypted-native.dll" : "encrypted-managed.dll");
            Protector.Protect(input, output, selection, virtualize:true, native:native, encryption:authority);
            byte[] image = File.ReadAllBytes(output);
            Check(image.AsSpan().IndexOf(key) < 0, "Raw program key present in output.");
            using (var module = ModuleDefinition.ReadModule(output))
            {
                var method = Protector.Methods(module).Single(m => m.Name == "Branches");
                var extracted = EncryptedRecoveryProbe.Extract(method);
                Check(extracted.KeyId == authority.KeyId, "Adaptive probe did not find expected key identity.");
                byte[] bytes = Convert.FromBase64String(extracted.Envelope);
                byte[] plaintext = new byte[bytes.Length - 36];
                using var cipher = new AesGcm(key, 16);
                cipher.Decrypt(bytes.AsSpan(8,12), bytes.AsSpan(20, plaintext.Length), bytes.AsSpan(bytes.Length-16),
                    plaintext, EncryptedIntegerMachine.AssociatedData(extracted.KeyId, extracted.Context));
                Check(BitConverter.ToInt32(plaintext,20) > 0, "External-key static recovery failed.");
                CryptographicOperations.ZeroMemory(plaintext);
                Console.WriteLine("THREAT BOUNDARY: adaptive static probe extracts ciphertext; possession of external key recovers VM plaintext.");
            }
            var load = new AssemblyLoadContext("encrypted-vm-" + native, isCollectible:true);
            try
            {
                var type = load.LoadFromAssemblyPath(output).GetType(typeof(Cases).FullName!)!;
                Check(Equals(Invoke(type, "Arithmetic", [1,2]), typeof(UnauthorizedAccessException).FullName),
                    "Compiled encrypted wrapper ran without provisioning.");
                using (native ? EncryptedIntegerMachine.RegisterNativeKey(key) : EncryptedIntegerMachine.RegisterKey(key))
                {
                    var random = new Random(839);
                    foreach (int value in new[] { int.MinValue,int.MaxValue,-1,0,1,239,-239 }
                        .Concat(Enumerable.Range(0,100).Select(_ => (int)random.NextInt64(int.MinValue,(long)int.MaxValue+1))))
                        foreach (string name in names)
                        {
                            object[] arguments = typeof(Cases).GetMethod(name)!.GetParameters().Length == 2 ? [value,unchecked(value*17)] : [value];
                            Check(Equals(Invoke(type,name,arguments),Invoke(typeof(Cases),name,arguments)), "Encrypted VM result/exception mismatch: " + name);
                        }
                }
                Check(Equals(Invoke(type,"Arithmetic",[1,2]), typeof(UnauthorizedAccessException).FullName),
                    "Compiled wrapper retained a usable key after disposal.");
            }
            finally { load.Unload(); }
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        Console.WriteLine($"Encrypted {(native ? "native" : "managed")} VM suite: {checks} authentication/execution checks passed.");
        return checks;
    }
    private static object? Invoke(Type type, string name, object[] args)
    {
        try { return type.GetMethod(name)!.Invoke(null,args); }
        catch (TargetInvocationException error) { return error.InnerException!.GetType().FullName; }
    }
}
