using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Fixture;
using Durevo.Runtime;

internal static class StringVmSuite
{
    internal static int Run(string root, bool native)
    {
        int checks = 0;
        void Check(bool condition, string message) { checks++; if (!condition) throw new Exception(message); }
        string input = typeof(StringCases).Assembly.Location;
        var analyzed = ProtectionAnalysis.Analyze(input);
        var selected = analyzed.Methods.Where(m => m.Signature.Contains("Durevo.Fixture.StringCases::") &&
            m.IntegerVmEligible).Select(m => m.Signature).ToArray();
        Check(selected.Length == 8, "String/scalar eligibility mismatch.");
        Check(!analyzed.Methods.Single(m => m.Signature.Contains("::UnsupportedText(")).IntegerVmEligible,
            "General string call accidentally accepted.");
        string?[] samples = [null, "", "abc", "😀x", "\0a\0", "\ud800", "\udfff", "абв (x,y)"];
        var random = new Random(721);
        samples = samples.Concat(Enumerable.Range(0, 80).Select(_ => (string?)new string(
            Enumerable.Range(0, random.Next(1, 80)).Select(_ => (char)random.Next(65536)).ToArray()))).ToArray();
        foreach (bool encrypted in new[] { false, true })
        {
            byte[] key = RandomNumberGenerator.GetBytes(32);
            using var encryption = new VmEncryptionKey(key);
            string output = Path.Combine(root, $"strings-{native}-{encrypted}.dll");
            Protector.Protect(input, output, selected, virtualize:true, native:native, encryption:encrypted ? encryption : null);
            var load = new AssemblyLoadContext("strings", true);
            try
            {
                var target = load.LoadFromAssemblyPath(output).GetType(typeof(StringCases).FullName!)!;
                if (encrypted)
                    Check(Equals(Invoke(target, "TextLength", ["abc"]), typeof(UnauthorizedAccessException).FullName),
                        "String wrapper ran without a key.");
                using var lease = encrypted ? native ? EncryptedIntegerMachine.RegisterNativeKey(key) :
                    EncryptedIntegerMachine.RegisterKey(key) : null;
                foreach (string? sample in samples)
                {
                    Compare("TextLength", [sample]);
                    Compare("IsMissing", [sample]);
                    Compare("SameReference", [sample, sample]);
                    Compare("SameReference", [sample, sample == null ? null : new string(sample.ToCharArray())]);
                    foreach (int index in new[] { -1, 0, 1, (sample?.Length ?? 0) - 1, sample?.Length ?? 0, int.MaxValue })
                    {
                        Compare("TextAt", [sample, index]);
                        Compare("TwoTexts", [sample, index, "😀a\0", 'a', true]);
                        Compare("TwoTexts", [sample, index, null, '\0', false]);
                    }
                    foreach (char needle in new[] { '\0', 'a', '\ud800', '\udfff', 'я' })
                        Compare("FindChar", [sample, needle]);
                }
                foreach (int value in new[] { int.MinValue, -65537, -1, 0, 1, 255, 256, 65535, 65536, int.MaxValue })
                {
                    Compare("ScalarChar", [value]); Compare("ScalarBool", [false, value]); Compare("ScalarBool", [true, value]);
                }
                void Compare(string name, object?[] args) =>
                    Check(Equals(Invoke(target, name, args), Invoke(typeof(StringCases), name, args)),
                        $"String VM mismatch: native={native}, encrypted={encrypted}, method={name}.");
            }
            finally { load.Unload(); CryptographicOperations.ZeroMemory(key); }
        }
        Console.WriteLine($"String/scalar VM suite ({(native ? "native" : "managed")}): {checks} differential checks.");
        return checks;
    }
    internal static object? Invoke(Type type, string name, object?[] arguments)
    {
        try { return type.GetMethod(name)!.Invoke(null, arguments); }
        catch (TargetInvocationException error) { return error.InnerException!.GetType().FullName; }
    }
}
