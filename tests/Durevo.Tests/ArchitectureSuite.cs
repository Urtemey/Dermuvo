using Durevo.Core;
using Mono.Cecil;
using Mono.Cecil.Cil;

internal static class ArchitectureSuite
{
    internal static int Run(string root)
    {
        int checks = 0;
        void Check(bool value, string text) { checks++; if (!value) throw new Exception(text); }
        using var module = ModuleDefinition.CreateModule("ArchitectureFixture", ModuleKind.Dll);
        var type = new TypeDefinition("Product.Internal", "Planner", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        MethodDefinition Add(string name, MethodAttributes flags)
        {
            var method = new MethodDefinition(name, flags | MethodAttributes.Static, module.TypeSystem.Int32);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(method); return method;
        }
        var hidden = Add("CalculateSecretRoute", MethodAttributes.Private);
        Add("Awake", MethodAttributes.Private);
        Add("PublicEntry", MethodAttributes.Public);
        string file = Path.Combine(root, "architecture-fixture.dll");
        module.Write(file);
        var initial = ArchitectureAnalysis.Analyze(file);
        Check(initial.Types.Single().Name == "Product.Internal.Planner", "Lost type exposure.");
        Check(initial.ReviewCandidates == 1, "Unexpected review candidates.");
        Check(initial.Types[0].Methods.Single(m => m.Name == "Awake").ContractHints.Contains("unity-message-name"), "Unity callback not flagged.");
        Check(initial.Types[0].Methods.Single(m => m.Name == "PublicEntry").ContractHints.Contains("non-private-contract"), "Public contract not flagged.");
        hidden.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Pop));
        hidden.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Ldstr, hidden.Name));
        module.Write(file);
        var literal = ArchitectureAnalysis.Analyze(file);
        Check(literal.ReviewCandidates == 0, "Literal name reference silently eligible.");
        Check(literal.Types[0].Methods[0].ContractHints.Contains("literal-name-reference"), "Literal hint absent.");
        var getMethod = module.ImportReference(typeof(Type).GetMethod("GetMethod", [typeof(string)])!);
        var il = hidden.Body.GetILProcessor();
        il.InsertBefore(hidden.Body.Instructions[0], Instruction.Create(OpCodes.Ldnull));
        il.InsertBefore(hidden.Body.Instructions[1], Instruction.Create(OpCodes.Ldstr, "anything"));
        il.InsertBefore(hidden.Body.Instructions[2], Instruction.Create(OpCodes.Callvirt, getMethod));
        il.InsertBefore(hidden.Body.Instructions[3], Instruction.Create(OpCodes.Pop));
        module.Write(file);
        var reflection = ArchitectureAnalysis.Analyze(file);
        Check(reflection.DynamicBindingCalls.Length == 1, "Reflection call not inventoried.");
        Check(reflection.Types[0].Methods.All(m => m.ContractHints.Contains("module-dynamic-binding-review")), "Dynamic review not propagated.");
        Console.WriteLine($"Architecture inventory: {checks} exposure/contract checks passed.");
        return checks;
    }
}
