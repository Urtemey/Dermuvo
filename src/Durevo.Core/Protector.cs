using System.Security.Cryptography;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Durevo.Core;

public sealed record ProtectionReport(int Methods, int Strings, int Integers, int Blocks,
    string InputSha256, string OutputSha256);

public static class Protector
{
    internal const string Marker = "Durevo.Transform.v1";
    static readonly Dictionary<Code, OpCode> LongBranches = new()
    {
        [Code.Br_S]=OpCodes.Br, [Code.Brfalse_S]=OpCodes.Brfalse, [Code.Brtrue_S]=OpCodes.Brtrue,
        [Code.Beq_S]=OpCodes.Beq, [Code.Bge_S]=OpCodes.Bge, [Code.Bgt_S]=OpCodes.Bgt,
        [Code.Ble_S]=OpCodes.Ble, [Code.Blt_S]=OpCodes.Blt, [Code.Bne_Un_S]=OpCodes.Bne_Un,
        [Code.Bge_Un_S]=OpCodes.Bge_Un, [Code.Bgt_Un_S]=OpCodes.Bgt_Un,
        [Code.Ble_Un_S]=OpCodes.Ble_Un, [Code.Blt_Un_S]=OpCodes.Blt_Un,
        [Code.Leave_S]=OpCodes.Leave
    };

    public static string MethodIdentity(MethodDefinition method) => method.FullName +
        (method.HasGenericParameters ? " [generic-arity:" + method.GenericParameters.Count + "]" : "");

    public static IEnumerable<MethodDefinition> Methods(ModuleDefinition module) =>
        module.Types.SelectMany(AllTypes).SelectMany(t => t.Methods);
    static IEnumerable<TypeDefinition> AllTypes(TypeDefinition type)
    {
        yield return type;
        foreach (var child in type.NestedTypes.SelectMany(AllTypes)) yield return child;
    }

    public static ProtectionReport Protect(string input, string output, IReadOnlyCollection<string> signatures, bool virtualize = false, bool native = false, VmEncryptionKey? encryption = null, bool verifiedNative = false, IReadOnlyDictionary<string, VmEncryptionKey>? methodKeys = null)
    {
        // Snapshot with ordinal matching; never silently fall back to a shared key.
        Dictionary<string, VmEncryptionKey>? selectedKeys = null;
        if (methodKeys != null)
        {
            if (!virtualize || encryption != null)
                throw new ArgumentException("Method keys require virtualization and cannot be combined with a shared key.");
            selectedKeys = new Dictionary<string, VmEncryptionKey>(methodKeys, StringComparer.Ordinal);
            if (selectedKeys.Count != signatures.Count || selectedKeys.Any(pair => pair.Value == null) ||
                signatures.Any(signature => !selectedKeys.ContainsKey(signature)))
                throw new ArgumentException("Method keys must exactly cover the selected signatures.");
        }
        if (verifiedNative && (!virtualize || !native || (encryption == null && selectedKeys == null))) throw new ArgumentException("Verified native execution requires encrypted native virtualization.");
        if (encryption != null && !virtualize) throw new ArgumentException("Encryption requires virtualization.");
        if (native && !virtualize) throw new ArgumentException("Native execution requires virtualization.");
        input = Path.GetFullPath(input); output = Path.GetFullPath(output);
        if (StringComparer.OrdinalIgnoreCase.Equals(input, output) || File.Exists(output))
            throw new InvalidOperationException("Output must be a new file; input is never overwritten.");
        if (signatures.Count == 0 || signatures.Distinct(StringComparer.Ordinal).Count() != signatures.Count)
            throw new ArgumentException("Select unique, exact method signatures.");
        var source = File.ReadAllBytes(input);
        using var stream = new MemoryStream(source, false);
        using var resolver = new DefaultAssemblyResolver();
        resolver.AddSearchDirectory(Path.GetDirectoryName(input)!);
        using var module = ModuleDefinition.ReadModule(stream, new ReaderParameters { InMemory = true, AssemblyResolver = resolver });
        if ((module.Attributes & ModuleAttributes.ILOnly) == 0 || module.Assembly is null)
            throw new NotSupportedException("Only managed assemblies are supported.");
        if (module.Assembly.Name.HasPublicKey)
            throw new NotSupportedException("Strong-named inputs require a future explicit re-signing workflow.");
        if (module.Resources.Any(r => r.Name == Marker))
            throw new NotSupportedException("Already transformed. Always use the original assembly.");
        var all = Methods(module).ToDictionary(MethodIdentity, StringComparer.Ordinal);
        var selected = signatures.Select(s => all.TryGetValue(s, out var m) ? m :
            throw new ArgumentException("Method not found: " + s)).ToArray();
        // Validate the entire selection before changing any method.
        foreach (var m in selected)
            if (BodyRejections(m).Count != 0)
                throw new NotSupportedException("Unsupported method body: " + m.FullName);

        if (virtualize) foreach (var m in selected) IntegerVirtualizer.Transform(module, m, native, selectedKeys == null ? encryption : selectedKeys[MethodIdentity(m)], verifiedNative);
        var bounds = selected.ToDictionary(MethodIdentity, m => checked(m.Body.MaxStackSize + 2));
        var decoder = CreateDecoder(module);
        bounds.Add(decoder.FullName, 16);
        int strings = 0, integers = 0, blocks = 0;
        foreach (var m in selected)
        {
            // Reserve a local to force a fat header with an explicit max-stack field.
            m.Body.Variables.Add(new VariableDefinition(module.TypeSystem.Int32));
            var il = m.Body.GetILProcessor();
            foreach (var instruction in m.Body.Instructions.ToArray())
            {
                if (LongBranches.TryGetValue(instruction.OpCode.Code, out var longForm))
                    instruction.OpCode = longForm;
                if (instruction.OpCode.Code == Code.Ldstr)
                {
                    var value = (string)instruction.Operand;
                    var key = RandomNumberGenerator.GetInt32(1, 65536);
                    var bytes = new byte[value.Length * 2];
                    for (int j = 0; j < value.Length; j++)
                    {
                        int encoded = value[j] ^ key;
                        bytes[2*j] = (byte)encoded; bytes[2*j+1] = (byte)(encoded >> 8);
                    }
                    instruction.Operand = Convert.ToBase64String(bytes);
                    var k = Instruction.Create(OpCodes.Ldc_I4, key);
                    il.InsertAfter(instruction, k);
                    il.InsertAfter(k, Instruction.Create(OpCodes.Call, decoder));
                    strings++;
                }
                else if (TryInteger(instruction, out int value))
                {
                    var key = BitConverter.ToInt32(RandomNumberGenerator.GetBytes(4));
                    instruction.OpCode = OpCodes.Ldc_I4; instruction.Operand = value ^ key;
                    var k = Instruction.Create(OpCodes.Ldc_I4, key);
                    il.InsertAfter(instruction, k);
                    il.InsertAfter(k, Instruction.Create(OpCodes.Xor));
                    integers++;
                }
            }
            if (PermutationSafety.CanReorder(m)) blocks += PermuteBlocks(m);
            m.Body.MaxStackSize += 2;
            m.DebugInformation.SequencePoints.Clear();
            m.DebugInformation.Scope = null;
        }
        module.Resources.Add(new EmbeddedResource(Marker, ManifestResourceAttributes.Private,
            Encoding.UTF8.GetBytes("Initial transformation pipeline; not a claim of cryptographic secrecy.")));
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        string temporary = output + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            module.Write(temporary, new WriterParameters { WriteSymbols = false });
            StackHeader.PreserveBounds(temporary, bounds);
            // Re-read to detect malformed metadata before publishing.
            using (var check = ModuleDefinition.ReadModule(temporary))
                if (check.Assembly.Name.Name != module.Assembly.Name.Name)
                    throw new InvalidDataException("Assembly identity changed.");
            var result = new ProtectionReport(selected.Length, strings, integers, blocks,
                Convert.ToHexString(SHA256.HashData(source)),
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(temporary))));
            File.Move(temporary, output, false);
            return result;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public static IReadOnlyList<string> BodyRejections(MethodDefinition method)
    {
        var reasons = new List<string>();
        if (!method.HasBody) { reasons.Add("body:missing"); return reasons; }
        if (method.Body.Instructions.Any(i => i.OpCode.OpCodeType == OpCodeType.Prefix)) reasons.Add("body:prefix");
        if (method.Body.Instructions.Any(i => i.OpCode.Code is Code.Jmp or Code.Calli)) reasons.Add("body:indirect-control-flow");
        return reasons;
    }

    static bool TryInteger(Instruction i, out int value)
    {
        value = i.OpCode.Code switch
        {
            Code.Ldc_I4_M1 => -1, Code.Ldc_I4_0 => 0, Code.Ldc_I4_1 => 1, Code.Ldc_I4_2 => 2,
            Code.Ldc_I4_3 => 3, Code.Ldc_I4_4 => 4, Code.Ldc_I4_5 => 5, Code.Ldc_I4_6 => 6,
            Code.Ldc_I4_7 => 7, Code.Ldc_I4_8 => 8,
            Code.Ldc_I4 => (int)i.Operand, Code.Ldc_I4_S => (sbyte)i.Operand, _ => 0
        };
        return i.OpCode.Code is >= Code.Ldc_I4_M1 and <= Code.Ldc_I4;
    }

    static int PermuteBlocks(MethodDefinition method)
    {
        var instructions = method.Body.Instructions.ToArray();
        if (instructions.Length == 0) return 0;
        // Keep every EH boundary at the first instruction of its original interval.
        // This preserves nesting, catch order, filter ranges and exclusive end anchors.
        var boundaries = new HashSet<Instruction>();
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            foreach (var anchor in new[] { handler.TryStart, handler.TryEnd, handler.HandlerStart,
                handler.HandlerEnd, handler.FilterStart })
                if (anchor != null) boundaries.Add(anchor);
        }
        var cuts = Enumerable.Range(0, instructions.Length)
            .Where(i => i == 0 || boundaries.Contains(instructions[i])).Append(instructions.Length).ToArray();
        var output = new List<Instruction>();
        int count = 0;
        for (int i = 0; i < cuts.Length - 1; i++)
            count += PermuteSegment(instructions[cuts[i]..cuts[i + 1]], output,
                method.Body.HasExceptionHandlers);
        method.Body.Instructions.Clear();
        foreach (var instruction in output) method.Body.Instructions.Add(instruction);
        return count;
    }

    static int PermuteSegment(Instruction[] instructions, List<Instruction> output, bool pinLast)
    {
        var leaders = new HashSet<Instruction> { instructions[0] };
        for (int i = 0; i < instructions.Length; i++)
        {
            var instruction = instructions[i];
            if (instruction.Operand is Instruction target) leaders.Add(target);
            if (instruction.Operand is Instruction[] targets) foreach (var t in targets) leaders.Add(t);
            if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch
                or FlowControl.Return or FlowControl.Throw)
                if (i + 1 < instructions.Length) leaders.Add(instructions[i+1]);
        }
        var blocks = new List<List<Instruction>>();
        foreach (var i in instructions)
        {
            if (leaders.Contains(i)) blocks.Add([]);
            blocks[^1].Add(i);
        }
        // Turn physical fallthrough into explicit edges before relocating blocks.
        for (int i = 0; i < blocks.Count - 1; i++)
            if (blocks[i][^1].OpCode.FlowControl is not (FlowControl.Branch or FlowControl.Return or FlowControl.Throw))
                blocks[i].Add(Instruction.Create(OpCodes.Br, blocks[i+1][0]));
        // An interval's final block may fall through into a nested try. Keep it last,
        // and do not synthesize a branch across an EH boundary.
        var order = Enumerable.Range(1, Math.Max(0, blocks.Count - (pinLast ? 2 : 1))).ToArray();
        RandomNumberGenerator.Shuffle(order.AsSpan());
        output.AddRange(blocks[0]);
        foreach (int index in order) output.AddRange(blocks[index]);
        if (pinLast && blocks.Count > 1) output.AddRange(blocks[^1]);
        return blocks.Count;
    }

    static MethodDefinition CreateDecoder(ModuleDefinition module)
    {
        var ts = module.TypeSystem;
        // References use the input module's core-library scope, never the tool's .NET 10 runtime.
        var convert = new TypeReference("System", "Convert", module, ts.CoreLibrary);
        var fromBase64 = new MethodReference("FromBase64String", new ArrayType(ts.Byte), convert);
        fromBase64.Parameters.Add(new ParameterDefinition(ts.String));
        var ctor = new MethodReference(".ctor", ts.Void, ts.String) { HasThis = true };
        ctor.Parameters.Add(new ParameterDefinition(new ArrayType(ts.Char)));
        var intern = new MethodReference("Intern", ts.String, ts.String);
        intern.Parameters.Add(new ParameterDefinition(ts.String));
        var type = new TypeDefinition("", "_d" + Guid.NewGuid().ToString("N"),
            TypeAttributes.NotPublic | TypeAttributes.Abstract | TypeAttributes.Sealed, ts.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Decode", MethodAttributes.Assembly | MethodAttributes.Static, ts.String);
        method.Parameters.Add(new ParameterDefinition(ts.String));
        method.Parameters.Add(new ParameterDefinition(ts.Int32));
        type.Methods.Add(method);
        method.Body.InitLocals = true;
        var bytes = new VariableDefinition(new ArrayType(ts.Byte));
        var chars = new VariableDefinition(new ArrayType(ts.Char));
        var index = new VariableDefinition(ts.Int32);
        method.Body.Variables.Add(bytes); method.Body.Variables.Add(chars); method.Body.Variables.Add(index);
        var il = method.Body.GetILProcessor();
        var loop = Instruction.Create(OpCodes.Ldloc, chars);
        var condition = Instruction.Create(OpCodes.Ldloc, index);
        il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Call, fromBase64); il.Emit(OpCodes.Stloc, bytes);
        il.Emit(OpCodes.Ldloc, bytes); il.Emit(OpCodes.Ldlen); il.Emit(OpCodes.Conv_I4);
        il.Emit(OpCodes.Ldc_I4_2); il.Emit(OpCodes.Div); il.Emit(OpCodes.Newarr, ts.Char); il.Emit(OpCodes.Stloc, chars);
        il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Stloc, index); il.Emit(OpCodes.Br, condition);
        il.Append(loop); il.Emit(OpCodes.Ldloc, index);
        il.Emit(OpCodes.Ldloc, bytes); il.Emit(OpCodes.Ldloc, index); il.Emit(OpCodes.Ldc_I4_2);
        il.Emit(OpCodes.Mul); il.Emit(OpCodes.Ldelem_U1);
        il.Emit(OpCodes.Ldloc, bytes); il.Emit(OpCodes.Ldloc, index); il.Emit(OpCodes.Ldc_I4_2);
        il.Emit(OpCodes.Mul); il.Emit(OpCodes.Ldc_I4_1); il.Emit(OpCodes.Add); il.Emit(OpCodes.Ldelem_U1);
        il.Emit(OpCodes.Ldc_I4_8); il.Emit(OpCodes.Shl); il.Emit(OpCodes.Or);
        il.Emit(OpCodes.Ldarg_1); il.Emit(OpCodes.Xor); il.Emit(OpCodes.Conv_U2); il.Emit(OpCodes.Stelem_I2);
        il.Emit(OpCodes.Ldloc, index); il.Emit(OpCodes.Ldc_I4_1); il.Emit(OpCodes.Add); il.Emit(OpCodes.Stloc, index);
        il.Append(condition); il.Emit(OpCodes.Ldloc, chars); il.Emit(OpCodes.Ldlen); il.Emit(OpCodes.Conv_I4);
        il.Emit(OpCodes.Blt, loop);
        il.Emit(OpCodes.Ldloc, chars); il.Emit(OpCodes.Newobj, ctor); il.Emit(OpCodes.Call, intern); il.Emit(OpCodes.Ret);
        return method;
    }
}
