using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using Durevo.Core;

internal static class JuniorCoderAnalyzerProbe
{
    private sealed record Observation(bool IsError, int Line, string? Reason, string? Exception);
    internal static void Run(string input, string output)
    {
        input = Path.GetFullPath(input); output = Path.GetFullPath(output);
        if (Directory.Exists(output) || File.Exists(output)) throw new IOException("Probe output must be new.");
        Directory.CreateDirectory(output);
        var report = ProtectionAnalysis.Analyze(input);
        if (!report.Assembly.StartsWith("CodeAnalyzer,", StringComparison.Ordinal))
            throw new ArgumentException("Expected the actual CodeAnalyzer assembly snapshot.");
        var selections = report.Methods.Where(m => m.ObfuscationEligible &&
            m.Signature.Contains("JuniorCoder.Scripts.CodeAnalyzer.", StringComparison.Ordinal)).Select(m => m.Signature).ToArray();
        File.WriteAllLines(Path.Combine(output, "methods.txt"), selections);
        string?[] samples = [null, "", "up(1)\ndown(2)\n", "up(1)\ndown2)\n", "up(1)\ndown(2\n",
            "\r\n(", ")\r\n", "(())", ")((", "print('(')", "😀(привет)", "\0(()", "\ud800)", "x\r(y)\r\nz"];
        var random = new Random(71339);
        const string alphabet = "() abc123\r\n\t";
        samples = samples.Concat(Enumerable.Range(0, 500).Select(_ => (string?)new string(
            Enumerable.Range(0, random.Next(0, 200)).Select(_ => alphabet[random.Next(alphabet.Length)]).ToArray()))).ToArray();
        var originalContext = new AssemblyLoadContext("juniorcoder-original", true);
        int checks = 0;
        try
        {
            var original = originalContext.LoadFromAssemblyPath(input).GetType("JuniorCoder.Scripts.CodeAnalyzer.PythonCodeChecker", true)!;
            var baseline = samples.Select(s => Observe(original, s)).ToArray();
            if (baseline.Any(x => x.Exception != null))
                throw new Exception("Baseline failed to execute; missing dependencies are not a passing comparison.");
            if (baseline[2].IsError || !baseline[3].IsError || baseline[3].Line != 1 ||
                !baseline[4].IsError || baseline[4].Line != 1)
                throw new Exception("Actual assembly failed known bracket scenarios.");
            checks += 3;
            for (int round = 0; round < 8; round++)
            {
                string transformed = Path.Combine(output, "protected-" + round + ".dll");
                var protectedReport = Protector.Protect(input, transformed, selections);
                var context = new AssemblyLoadContext("juniorcoder-protected-" + round, true);
                try
                {
                    var target = context.LoadFromAssemblyPath(transformed).GetType(original.FullName!, true)!;
                    for (int i = 0; i < samples.Length; i++)
                    {
                        if (Observe(target, samples[i]) != baseline[i]) throw new Exception($"Behavior changed: round={round}, sample={i}");
                        checks++;
                    }
                }
                finally { context.Unload(); }
                File.WriteAllText(Path.Combine(output, "protection-" + round + ".json"),
                    JsonSerializer.Serialize(protectedReport, new JsonSerializerOptions { WriteIndented = true }));
            }
            string afterHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(input)));
            if (afterHash != report.Sha256) throw new Exception("Source snapshot changed.");
            var evidence = new { Input = input, InputSha256 = report.Sha256, report.ModuleId, Methods = selections,
                Rounds = 8, Samples = samples.Length, Comparisons = checks,
                Scope = "Cached actual CodeAnalyzer DLL, .NET differential execution only. EH bracket-analysis method is included when eligible. Not Unity/game acceptance or reverse-engineering resistance." };
            File.WriteAllText(Path.Combine(output, "evidence.json"),
                JsonSerializer.Serialize(evidence, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"PASS: actual JuniorCoder CodeAnalyzer; {selections.Length} selected methods, 8 transformed assemblies, {checks} checks.");
            Console.WriteLine("Evidence: " + Path.Combine(output, "evidence.json"));
        }
        finally { originalContext.Unload(); }
    }
    private static Observation Observe(Type type, string? input)
    {
        try
        {
            object instance = Activator.CreateInstance(type)!;
            object value = type.GetMethod("RunAnalyzer")!.Invoke(instance, [input])!;
            Type result = value.GetType();
            return new((bool)result.GetProperty("IsError")!.GetValue(value)!,
                (int)result.GetProperty("ErrorLineIndex")!.GetValue(value)!,
                (string?)result.GetProperty("ErrorReason")!.GetValue(value), null);
        }
        catch (TargetInvocationException ex) { return new(false, -1, null, ex.InnerException!.GetType().FullName); }
    }
}
