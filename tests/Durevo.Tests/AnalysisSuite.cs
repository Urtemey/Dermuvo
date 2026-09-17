using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Fixture;

internal static class AnalysisSuite
{
    internal static int Run(string root)
    {
        int checks = 0;
        void Check(bool value, string message) { checks++; if (!value) throw new Exception(message); }
        string input = typeof(Cases).Assembly.Location;
        string hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(input)));
        var report = ProtectionAnalysis.Analyze(input);
        Check(report.Sha256 == hash && report.AssemblyBlockers.Length == 0, "Analysis identity mismatch.");
        Check(report.Methods.Single(m => m.Signature.Contains("::Arithmetic(")).IntegerVmEligible, "Arithmetic rejected by analysis.");
        Check(report.Methods.Single(m => m.Signature.Contains("::Unsupported(")).ObfuscationEligible, "EH basic transformation rejected.");
        Check(!report.Methods.Single(m => m.Signature.Contains("::Switch(")).IntegerVmEligible, "String result falsely VM eligible.");
        // Every declared VM candidate must actually pass the transform, not a duplicated opcode table.
        foreach (var method in report.Methods.Where(m => m.IntegerVmEligible))
        {
            string output = Path.Combine(root, "analysis-vm-" + checks + ".dll");
            Protector.Protect(input, output, [method.Signature], virtualize: true);
            Check(File.Exists(output), "Eligible VM method failed to transform.");
        }
        string protectedPath = Path.Combine(root, "analysis-transformed.dll");
        Protector.Protect(input, protectedPath, [report.Methods.First(m => m.IntegerVmEligible).Signature]);
        var transformed = ProtectionAnalysis.Analyze(protectedPath);
        Check(transformed.AssemblyBlockers.Contains("assembly:already-transformed") &&
            transformed.ObfuscationEligible == 0 && transformed.IntegerVmEligible == 0, "Repeated transform eligibility reported.");
        Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(input))) == hash, "Analysis mutated input.");
        Console.WriteLine($"Static protection analysis suite: {checks} checks passed.");
        return checks;
    }
}
