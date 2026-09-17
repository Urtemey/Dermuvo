using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using Durevo.Core;
using Durevo.Runtime;

internal static class JuniorCoderStringProbe
{
    private const string TypeName = "JuniorCoder.Scripts.Game.LogicLua.PythonCodeHandlerBeforeLaunch";
    private const string MethodName = "HasMultipleTopLevelArguments";
    internal static void Run(string input, string output)
    {
        input = Path.GetFullPath(input); output = Path.GetFullPath(output);
        if (Directory.Exists(output) || File.Exists(output)) throw new IOException("Output must be new.");
        var analysis = ProtectionAnalysis.Analyze(input);
        var selected = analysis.Methods.Single(m => m.Signature.Contains(TypeName + "::" + MethodName + "("));
        if (!selected.IntegerVmEligible) throw new NotSupportedException(string.Join(", ", selected.IntegerVmBlockers));
        Directory.CreateDirectory(output);
        string?[] samples = [null, "", "say('hello')", "say('hello', 2)", "say('a,b')", "say(f(1,2))",
            "say(f(1,2), 3)", "say([1,2])", "say({1:2,3:4})", "say(\"a,\\\"b\")", "say(\"a,\\\"b\", 2)",
            "say('😀,я')", "say('😀,я', 1)", "say('\0,\ud800')", "say('\0,\ud800',1)", "say(", "say(a)", "say(a,b"];
        var random = new Random(93713);
        const string alphabet = "()[]{},'\\\" abc123";
        samples = samples.Concat(Enumerable.Range(0, 1000).Select(_ => (string?)("say(" + new string(
            Enumerable.Range(0, random.Next(0, 150)).Select(_ => alphabet[random.Next(alphabet.Length)]).ToArray()) + ")"))).ToArray();
        int checks = 0;
        var originalLoad = new AssemblyLoadContext("real-string-original", true);
        var reports = new List<object>();
        try
        {
            MethodInfo original = GetMethod(originalLoad.LoadFromAssemblyPath(input));
            object?[] expected = samples.Select(s => Invoke(original, s)).ToArray();
            if (!Equals(expected[0], typeof(NullReferenceException).FullName) ||
                !Equals(expected[2], false) || !Equals(expected[3], true) ||
                !Equals(expected[4], false) || !Equals(expected[5], false) || !Equals(expected[6], true))
                throw new Exception("Real baseline failed expected parsing cases.");
            checks += 7;
            foreach (bool native in new[] { false, true })
            foreach (bool encrypted in new[] { false, true })
            {
                byte[] key = RandomNumberGenerator.GetBytes(32);
                using var authority = new VmEncryptionKey(key);
                string transformed = Path.Combine(output, $"game-{native}-{encrypted}.dll");
                var report = Protector.Protect(input, transformed, [selected.Signature], virtualize:true,
                    native:native, encryption:encrypted ? authority : null);
                var load = new AssemblyLoadContext("real-string-" + native + encrypted, true);
                try
                {
                    MethodInfo target = GetMethod(load.LoadFromAssemblyPath(transformed));
                    if (encrypted)
                    {
                        if (!Equals(Invoke(target, samples[3]), typeof(UnauthorizedAccessException).FullName))
                            throw new Exception("Encrypted actual method bypassed missing key.");
                        checks++;
                    }
                    using (var lease = encrypted ? native ? EncryptedIntegerMachine.RegisterNativeKey(key) :
                        EncryptedIntegerMachine.RegisterKey(key) : null)
                    {
                        for (int i = 0; i < samples.Length; i++)
                        {
                            if (!Equals(Invoke(target, samples[i]), expected[i]))
                                throw new Exception($"Actual parsing behavior changed: native={native}, encrypted={encrypted}, sample={i}");
                            checks++;
                        }
                    }
                    if (encrypted)
                    {
                        if (!Equals(Invoke(target, samples[3]), typeof(UnauthorizedAccessException).FullName))
                            throw new Exception("Encrypted actual method retained a disposed key.");
                        checks++;
                    }
                    reports.Add(new { Native = native, Encrypted = encrypted, Protection = report });
                }
                finally { load.Unload(); CryptographicOperations.ZeroMemory(key); }
            }
            if (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(input))) != analysis.Sha256)
                throw new Exception("Input snapshot changed.");
            File.WriteAllText(Path.Combine(output, "evidence.json"), JsonSerializer.Serialize(new {
                Input=input, analysis.Sha256, analysis.ModuleId, Method=selected.Signature,
                Samples=samples.Length, Checks=checks, Modes=reports,
                Scope="One actual cached JuniorCoder cooperative Python parsing method; .NET differential execution, not entire gameplay or protection-strength acceptance."
            }, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"PASS: actual cooperative Python parser virtualized in four modes; {samples.Length} inputs, {checks} checks.");
        }
        finally { originalLoad.Unload(); }
    }
    private static MethodInfo GetMethod(Assembly assembly) =>
        assembly.GetType(TypeName, true)!.GetMethod(MethodName, BindingFlags.NonPublic | BindingFlags.Static)!;
    private static object? Invoke(MethodInfo method, string? text)
    {
        try { return method.Invoke(null, [text]); }
        catch (TargetInvocationException ex) { return ex.InnerException!.GetType().FullName; }
    }
}
