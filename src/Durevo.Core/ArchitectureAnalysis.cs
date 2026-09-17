using Mono.Cecil;
using Mono.Cecil.Cil;
using System.Security.Cryptography;

namespace Durevo.Core;

public sealed record ArchitectureMethod(string Signature, string Name, string Visibility,
    string[] ContractHints, bool PrivateStaticReviewCandidate);
public sealed record ArchitectureType(string Name, string? BaseType, string[] Interfaces,
    string[] Attributes, string[] Fields, string[] Properties, string[] Events, ArchitectureMethod[] Methods);
public sealed record ArchitectureReport(string Assembly, string Sha256, string[] References,
    string[] Resources, string[] DynamicBindingCalls, ArchitectureType[] Types)
{
    public string Scope => "Developer-only architecture inventory. Candidates require manual contract review; not rename authorization or security acceptance.";
    public int ReviewCandidates => Types.Sum(t => t.Methods.Count(m => m.PrivateStaticReviewCandidate));
}

// Deliberately does not resolve external assemblies or claim absence of dynamic contracts.
public static class ArchitectureAnalysis
{
    static readonly HashSet<string> UnityMessages = new(StringComparer.Ordinal) {
        "Awake", "Start", "Update", "FixedUpdate", "LateUpdate", "OnEnable", "OnDisable",
        "OnDestroy", "OnValidate", "Reset", "OnGUI", "OnApplicationQuit", "OnApplicationPause",
        "OnApplicationFocus", "OnBeforeSerialize", "OnAfterDeserialize" };

    public static ArchitectureReport Analyze(string input)
    {
        byte[] bytes = File.ReadAllBytes(input);
        using var module = ModuleDefinition.ReadModule(new MemoryStream(bytes, false), new ReaderParameters { InMemory = true });
        var types = module.Types.SelectMany(Flatten).Where(t => t.Name != "<Module>").ToArray();
        var instructions = types.SelectMany(t => t.Methods).Where(m => m.HasBody)
            .SelectMany(m => m.Body.Instructions).ToArray();
        var literals = instructions.Where(i => i.OpCode.Code == Code.Ldstr).Select(i => (string)i.Operand).ToHashSet(StringComparer.Ordinal);
        var dynamicCalls = instructions.Select(i => i.Operand).OfType<MethodReference>()
            .Where(IsDynamic).Select(m => m.FullName).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var result = types.Select(t => new ArchitectureType(t.FullName, t.BaseType?.FullName,
            t.Interfaces.Select(i => i.InterfaceType.FullName).ToArray(),
            t.CustomAttributes.Select(a => a.AttributeType.FullName).ToArray(),
            t.Fields.Select(f => f.FullName).ToArray(), t.Properties.Select(p => p.FullName).ToArray(),
            t.Events.Select(e => e.FullName).ToArray(),
            t.Methods.Select(m => Describe(t, m, literals, dynamicCalls.Length > 0)).ToArray())).ToArray();
        return new ArchitectureReport(module.Assembly?.Name.FullName ?? module.Name,
            Convert.ToHexString(SHA256.HashData(bytes)), module.AssemblyReferences.Select(r => r.FullName).ToArray(),
            module.Resources.Select(r => r.Name).ToArray(), dynamicCalls, result);
    }

    private static ArchitectureMethod Describe(TypeDefinition t, MethodDefinition m, HashSet<string> literals, bool dynamic)
    {
        var hints = new List<string>();
        if (!m.IsPrivate) hints.Add("non-private-contract");
        if (!m.IsStatic) hints.Add("instance-dispatch-review");
        if (m.IsConstructor || m.IsSpecialName || m.IsRuntimeSpecialName) hints.Add("runtime-or-property-event-name");
        if (m.IsVirtual || m.HasOverrides) hints.Add("virtual-or-interface-contract");
        if (m.HasGenericParameters || t.HasGenericParameters) hints.Add("generic-context-review");
        if (!m.HasBody || m.IsPInvokeImpl) hints.Add("external-or-missing-body");
        if (m.HasCustomAttributes || t.HasCustomAttributes) hints.Add("attribute-contract-review");
        if (t.BaseType != null && t.BaseType.FullName != "System.Object") hints.Add("inheritance-contract-review");
        if (t.HasInterfaces) hints.Add("interface-context-review");
        if (literals.Contains(m.Name) || literals.Contains(t.FullName) || literals.Contains(t.Name))
            hints.Add("literal-name-reference");
        if (UnityMessages.Contains(m.Name) || m.Name.StartsWith("OnTrigger", StringComparison.Ordinal) ||
            m.Name.StartsWith("OnCollision", StringComparison.Ordinal)) hints.Add("unity-message-name");
        if (dynamic) hints.Add("module-dynamic-binding-review");
        return new ArchitectureMethod(m.FullName, m.Name,
            m.IsPublic ? "public" : m.IsPrivate ? "private" : m.IsAssembly ? "internal" : "protected-or-mixed",
            hints.ToArray(), hints.Count == 0);
    }

    private static bool IsDynamic(MethodReference m)
    {
        string type = m.DeclaringType.FullName;
        return type.StartsWith("System.Reflection.", StringComparison.Ordinal) ||
            type.StartsWith("IronPython.", StringComparison.Ordinal) ||
            type.StartsWith("Microsoft.Scripting.", StringComparison.Ordinal) ||
            type.StartsWith("MoonSharp.", StringComparison.Ordinal) ||
            type == "System.Type" && (m.Name.StartsWith("Get", StringComparison.Ordinal) || m.Name == "InvokeMember") ||
            type == "System.Activator" ||
            type.StartsWith("UnityEngine.", StringComparison.Ordinal) &&
                m.Name is "SendMessage" or "BroadcastMessage" or "Invoke" or "StartCoroutine";
    }
    private static IEnumerable<TypeDefinition> Flatten(TypeDefinition t)
    {
        yield return t;
        foreach (var child in t.NestedTypes.SelectMany(Flatten)) yield return child;
    }
}
