using Durevo.Core;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System.Runtime.Loader;

internal static class StackEdgeSuite
{
    internal static int Run(string root)
    {
        string input = Path.Combine(root, "stack-edge-input.dll");
        using (var module = ModuleDefinition.CreateModule("StackEdges", ModuleKind.Dll))
        {
            var type = new TypeDefinition("Fixture", "Edges", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(type);
            var method = new MethodDefinition("Choose", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Int32);
            method.Parameters.Add(new ParameterDefinition(module.TypeSystem.Boolean));
            type.Methods.Add(method);
            var il = method.Body.GetILProcessor();
            var otherwise = Instruction.Create(OpCodes.Ldc_I4_2);
            il.Emit(OpCodes.Ldc_I4, 10); il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Brfalse, otherwise);
            il.Emit(OpCodes.Ldc_I4_1); il.Emit(OpCodes.Add); il.Emit(OpCodes.Ret);
            il.Append(otherwise); il.Emit(OpCodes.Add); il.Emit(OpCodes.Ret);
            module.Write(input);
        }
        var signatures = ProtectionAnalysis.Analyze(input).Methods.Select(m => m.Signature).ToArray();
        for (int i = 0; i < 16; i++)
        {
            string output = Path.Combine(root, "stack-edge-" + i + ".dll");
            var report = Protector.Protect(input, output, signatures);
            if (report.Blocks != 0 || report.Integers == 0) throw new Exception("Unsafe stack edges were permuted or constants unprotected.");
            var context = new AssemblyLoadContext("stack-edge-" + i, true);
            try
            {
                var method = context.LoadFromAssemblyPath(output).GetType("Fixture.Edges")!.GetMethod("Choose")!;
                if (!Equals(method.Invoke(null, new object[] { true }), 11) ||
                    !Equals(method.Invoke(null, new object[] { false }), 12)) throw new Exception("Stack edge semantics changed.");
            }
            finally { context.Unload(); }
        }
        return 48;
    }
}
