using System.Security.Cryptography;
using System.Text.Json;
using Durevo.Core;
using Durevo.Fixture;
using Mono.Cecil;
using Mono.Cecil.Cil;

internal static class ExceptionFixtures
{
    internal static void Write(string output, string? cipherAssembly = null)
    {
        Directory.CreateDirectory(output);
        string input = Path.Combine(output, "eh-original.dll");
        if (File.Exists(input)) throw new IOException("EH fixture already exists.");
        WriteInput(input);
        using (var module = ModuleDefinition.ReadModule(input))
        {
            string[] selected = Protector.Methods(module).Where(m => m.DeclaringType.FullName == typeof(ExceptionCases).FullName && m.HasBody).Select(m => m.FullName).ToArray();
            for (int round = 0; round < 4; round++)
                Protector.Protect(input, Path.Combine(output, "eh-protected-" + round + ".dll"), selected);
        }
        if (cipherAssembly != null) WriteCipher(output, cipherAssembly);
    }
    // C# has no fault syntax. Emit a valid fixture to exercise that distinct EH kind.
    private static void WriteInput(string output)
    {
        using var module = ModuleDefinition.ReadModule(typeof(ExceptionCases).Assembly.Location);
        var type = module.Types.Single(t => t.FullName == typeof(ExceptionCases).FullName);
        var trace = type.Fields.Single(f => f.Name == "Trace");
        var method = new MethodDefinition("Fault", Mono.Cecil.MethodAttributes.Public | Mono.Cecil.MethodAttributes.Static, module.TypeSystem.String);
        method.Parameters.Add(new ParameterDefinition(module.TypeSystem.Int32));
        type.Methods.Add(method);
        var body = method.Body;
        body.InitLocals = true;
        body.Variables.Add(new VariableDefinition(module.TypeSystem.Int32));
        var il = body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, ""); il.Emit(OpCodes.Stsfld, trace);
        var start = Instruction.Create(OpCodes.Ldc_I4, 37);
        var fault = Instruction.Create(OpCodes.Ldstr, "fault");
        var end = Instruction.Create(OpCodes.Ldstr, "completed");
        il.Append(start); il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Div); il.Emit(OpCodes.Stloc_0);
        il.Emit(OpCodes.Leave, end);
        il.Append(fault); il.Emit(OpCodes.Stsfld, trace); il.Emit(OpCodes.Endfinally);
        il.Append(end); il.Emit(OpCodes.Ret);
        body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Fault) {
            TryStart = start, TryEnd = fault, HandlerStart = fault, HandlerEnd = end
        });
        module.Write(output);
    }
    internal static void WriteCipher(string output, string cipherAssembly)
    {
        string hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(cipherAssembly)));
        using var cipher = ModuleDefinition.ReadModule(cipherAssembly);
        if (cipher.Assembly.Name.Name != "JuniorCoder.LicenseKey") throw new ArgumentException("Expected JuniorCoder.LicenseKey snapshot.");
        string[] methods = Protector.Methods(cipher).Where(m => m.DeclaringType.FullName == "StringCipher" && m.HasBody).Select(m => m.FullName).ToArray();
        if (methods.Length < 3) throw new InvalidDataException("Missing cipher methods.");
        File.Copy(cipherAssembly, Path.Combine(output, "cipher-original.dll"), false);
        var reports = new List<ProtectionReport>();
        for (int round = 0; round < 4; round++)
            reports.Add(Protector.Protect(cipherAssembly, Path.Combine(output, "cipher-protected-" + round + ".dll"), methods));
        if (hash != Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(cipherAssembly)))) throw new IOException("Source changed.");
        File.WriteAllText(Path.Combine(output, "cipher-evidence.json"), JsonSerializer.Serialize(new {
            Source = Path.GetFullPath(cipherAssembly), Sha256 = hash, cipher.Mvid, Methods = methods, Reports = reports,
            Scope = "Cached actual DLL basic transformation. Test fixture creation only; execution evidence is separate. Not license policy or game acceptance."
        }, new JsonSerializerOptions { WriteIndented = true }));
    }
}
