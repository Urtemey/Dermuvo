using Durevo.Core;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System.Runtime.Loader;

internal static class GenericIdentitySuite
{
    internal static int Run(string root)
    {
        string input = Path.Combine(root, "generic-input.dll"), output = Path.Combine(root, "generic-output.dll");
        using (var module = ModuleDefinition.CreateModule("GenericCollision", ModuleKind.Dll))
        {
            var type = new TypeDefinition("Fixture", "Overloads", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(type);
            for (int arity = 0; arity < 3; arity++)
            {
                var method = new MethodDefinition("Select", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Int32);
                for (int i = 0; i < arity; i++) method.GenericParameters.Add(new GenericParameter("T" + i, method));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, arity + 17));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                type.Methods.Add(method);
            }
            module.Write(input);
        }
        var analysis = ProtectionAnalysis.Analyze(input);
        var signatures = analysis.Methods.Select(m => m.Signature).ToArray();
        if (signatures.Distinct().Count() != 3) throw new Exception("Generic identities collide.");
        Protector.Protect(input, output, signatures);
        var context = new AssemblyLoadContext("generic-identity", true);
        try
        {
            var type = context.LoadFromAssemblyPath(output).GetType("Fixture.Overloads")!;
            foreach (var method in type.GetMethods().Where(m => m.Name == "Select"))
            {
                int arity = method.GetGenericArguments().Length;
                var callable = arity == 0 ? method : method.MakeGenericMethod(Enumerable.Repeat(typeof(int), arity).ToArray());
                if (!Equals(callable.Invoke(null, null), arity + 17)) throw new Exception("Generic overload semantics changed.");
            }
        }
        finally { context.Unload(); }
        Console.WriteLine("Generic method identity: three same-name overloads independently protected and executed.");
        return 4;
    }
}
