using System.Security.Cryptography;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Durevo.Core;

public sealed record MethodProtectionAnalysis(string Signature, int Instructions, bool CompilerGenerated,
    string[] ObfuscationBlockers, string[] IntegerVmBlockers)
{
    public bool ObfuscationEligible => ObfuscationBlockers.Length == 0;
    public bool IntegerVmEligible => ObfuscationEligible && IntegerVmBlockers.Length == 0;
}

public sealed record AssemblyProtectionAnalysis(string Assembly, string ModuleId, string Sha256, long Bytes,
    string[] AssemblyBlockers, MethodProtectionAnalysis[] Methods)
{
    public string Scope => "Static eligibility only; no runtime, protection-strength or product-value acceptance.";
    public int MethodsWithBodies => Methods.Count(m => m.Instructions > 0);
    public int ObfuscationEligible => AssemblyBlockers.Length == 0 ? Methods.Count(m => m.ObfuscationEligible) : 0;
    public int IntegerVmEligible => AssemblyBlockers.Length == 0 ? Methods.Count(m => m.IntegerVmEligible) : 0;
}

public static class ProtectionAnalysis
{
    public static AssemblyProtectionAnalysis Analyze(string input)
    {
        byte[] source = File.ReadAllBytes(input);
        using var module = ModuleDefinition.ReadModule(new MemoryStream(source, false),
            new ReaderParameters { InMemory = true });
        var blocked = new List<string>();
        if (module.Assembly is null || (module.Attributes & ModuleAttributes.ILOnly) == 0)
            blocked.Add("assembly:not-managed-only");
        if (module.Assembly?.Name.HasPublicKey == true) blocked.Add("assembly:strong-name");
        if (module.Resources.Any(r => r.Name == Protector.Marker)) blocked.Add("assembly:already-transformed");
        var methods = Protector.Methods(module).Select(m => new MethodProtectionAnalysis(
            Protector.MethodIdentity(m), m.HasBody ? m.Body.Instructions.Count : 0,
            m.CustomAttributes.Any(a => a.AttributeType.FullName == "System.Runtime.CompilerServices.CompilerGeneratedAttribute") ||
            m.DeclaringType.CustomAttributes.Any(a => a.AttributeType.FullName == "System.Runtime.CompilerServices.CompilerGeneratedAttribute"),
            Protector.BodyRejections(m).ToArray(), IntegerVirtualizer.RejectionReasons(m).ToArray())).ToArray();
        return new AssemblyProtectionAnalysis(module.Assembly?.Name.FullName ?? module.Name,
            module.Mvid.ToString("D"), Convert.ToHexString(SHA256.HashData(source)), source.LongLength, blocked.ToArray(), methods);
    }
}
