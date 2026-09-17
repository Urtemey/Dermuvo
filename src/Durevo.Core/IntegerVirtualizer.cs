using System.Security.Cryptography;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Durevo.Runtime;
using O = Durevo.Runtime.IntegerMachine.Operation;

namespace Durevo.Core;

public static class IntegerVirtualizer
{
    // Scalar VM with explicit UTF-16 string intrinsics; no general managed call/object bridge.
    public static void Transform(ModuleDefinition module, MethodDefinition method, bool native = false, VmEncryptionKey? encryption = null, bool verifiedNative = false)
    {
        if (verifiedNative && (!native || encryption == null)) throw new ArgumentException("Verified native execution requires encryption and native mode.");
        var reasons = RejectionReasons(method);
        if (reasons.Count != 0) throw new NotSupportedException("Unsupported VM method " + method.FullName + ": " + string.Join(", ", reasons));

        var original = method.Body;
        var indices = original.Instructions.Select((instruction, index) => (instruction, index: index*2))
            .ToDictionary(x => x.instruction, x => x.index);
        var code = new List<int>();
        foreach (var i in original.Instructions)
        {
            var (op, operand) = Translate(i, indices, method);
            code.Add((int)op); code.Add(operand);
        }
        int key = BitConverter.ToInt32(RandomNumberGenerator.GetBytes(4));
        for(int i=0;i<code.Count;i++) code[i] ^= unchecked(key + i * (int)0x9e3779b9);

        bool strings = method.Parameters.Any(p => p.ParameterType.MetadataType == MetadataType.String);
        string entry = encryption != null && native ? (verifiedNative ? "RunVerifiedNative" : "RunNative") : "Run";
        if (strings) entry += "Strings";
        var run = module.ImportReference((encryption != null ? typeof(EncryptedIntegerMachine) : native ? typeof(NativeIntegerMachine) : typeof(IntegerMachine)).GetMethod(entry)!);
        method.Body = new MethodBody(method) { InitLocals = false, MaxStackSize = 8 };
        var il = method.Body.GetILProcessor();
        VariableDefinition? stringTable = null, stringTokens = null;
        if (strings)
        {
            stringTable = new VariableDefinition(new ArrayType(module.TypeSystem.String));
            stringTokens = new VariableDefinition(new ArrayType(module.TypeSystem.Int32));
            method.Body.Variables.Add(stringTable); method.Body.Variables.Add(stringTokens);
            var textParameters = method.Parameters.Where(p => p.ParameterType.MetadataType == MetadataType.String).ToArray();
            il.Emit(OpCodes.Ldc_I4, textParameters.Length); il.Emit(OpCodes.Newarr, module.TypeSystem.String);
            for (int i = 0; i < textParameters.Length; i++)
            {
                il.Emit(OpCodes.Dup); il.Emit(OpCodes.Ldc_I4, i); il.Emit(OpCodes.Ldarg, textParameters[i]); il.Emit(OpCodes.Stelem_Ref);
            }
            il.Emit(OpCodes.Stloc, stringTable);
            il.Emit(OpCodes.Ldloc, stringTable);
            il.Emit(OpCodes.Call, module.ImportReference(typeof(StringReferences).GetMethod("CreateTokens")!));
            il.Emit(OpCodes.Stloc, stringTokens);
        }
        if (encryption != null)
        {
            string context = module.Assembly.Name.FullName + "|" + method.FullName;
            string envelope = encryption.Seal(code.ToArray(), original.Variables.Count,
                Math.Max(1, original.MaxStackSize), method.Parameters.Count, key, native, context);
            il.Emit(OpCodes.Ldstr, envelope);
            il.Emit(OpCodes.Ldstr, encryption.KeyId);
            il.Emit(OpCodes.Ldstr, context);
        }
        else
        {
        il.Emit(OpCodes.Ldc_I4, code.Count); il.Emit(OpCodes.Newarr, module.TypeSystem.Int32);
        for(int i=0;i<code.Count;i++)
        {
            il.Emit(OpCodes.Dup); il.Emit(OpCodes.Ldc_I4, i); il.Emit(OpCodes.Ldc_I4, code[i]); il.Emit(OpCodes.Stelem_I4);
        }
        }
        il.Emit(OpCodes.Ldc_I4, method.Parameters.Count); il.Emit(OpCodes.Newarr, module.TypeSystem.Int32);
        for(int i=0;i<method.Parameters.Count;i++)
        {
            il.Emit(OpCodes.Dup); il.Emit(OpCodes.Ldc_I4, i);
            if (method.Parameters[i].ParameterType.MetadataType == MetadataType.String)
            {
                il.Emit(OpCodes.Ldloc, stringTokens!);
                il.Emit(OpCodes.Ldc_I4, method.Parameters.Take(i).Count(p => p.ParameterType.MetadataType == MetadataType.String));
                il.Emit(OpCodes.Ldelem_I4);
            }
            else il.Emit(OpCodes.Ldarg, method.Parameters[i]);
            il.Emit(OpCodes.Stelem_I4);
        }
        if (encryption == null)
        {
        il.Emit(OpCodes.Ldc_I4, original.Variables.Count); il.Emit(OpCodes.Ldc_I4, Math.Max(1, original.MaxStackSize));
        il.Emit(OpCodes.Ldc_I4, key);
        }
        if (strings) il.Emit(OpCodes.Ldloc, stringTable!);
        il.Emit(OpCodes.Call, run); il.Emit(OpCodes.Ret);
        method.DebugInformation.SequencePoints.Clear(); method.DebugInformation.Scope = null;
    }

    public static IReadOnlyList<string> RejectionReasons(MethodDefinition method)
    {
        var reasons = new List<string>();
        if (!method.IsStatic) reasons.Add("vm:instance-method");
        if (method.HasGenericParameters || method.DeclaringType.HasGenericParameters) reasons.Add("vm:generic");
        if (!IsScalar(method.ReturnType)) reasons.Add("vm:return-type:" + method.ReturnType.FullName);
        foreach (var type in method.Parameters.Select(p => p.ParameterType).Where(t => !IsScalar(t) && t.MetadataType != MetadataType.String)
            .Select(t => t.FullName).Distinct()) reasons.Add("vm:parameter-type:" + type);
        if (!method.HasBody) { reasons.Add("vm:no-body"); return reasons; }
        if (method.Body.HasExceptionHandlers) reasons.Add("vm:exception-handlers");
        foreach (var type in method.Body.Variables.Select(v => v.VariableType).Where(t => !IsScalar(t))
            .Select(t => t.FullName).Distinct()) reasons.Add("vm:local-type:" + type);
        var indices = method.Body.Instructions.Select((i, n) => (i, n: n * 2)).ToDictionary(x => x.i, x => x.n);
        foreach (var instruction in method.Body.Instructions)
        {
            try { _ = Translate(instruction, indices, method); }
            catch (NotSupportedException) { reasons.Add("vm:opcode:" + instruction.OpCode.Code); }
        }
        return reasons.Distinct(StringComparer.Ordinal).ToArray();
    }

    static bool IsScalar(TypeReference type) => type.MetadataType is MetadataType.Int32 or MetadataType.Boolean or MetadataType.Char;

    static (O, int) Translate(Instruction i, Dictionary<Instruction,int> indices, MethodDefinition method)
    {
        if (i.OpCode.Code == Code.Callvirt && i.Operand is MethodReference call &&
            call.HasThis && !call.HasGenericParameters &&
            call.DeclaringType.Scope.Name == method.Module.TypeSystem.CoreLibrary.Name)
        {
            return call.FullName switch
            {
                "System.Int32 System.String::get_Length()" => (O.StringLength, 0),
                "System.Char System.String::get_Chars(System.Int32)" => (O.StringChar, 0),
                "System.Int32 System.String::IndexOf(System.Char)" => (O.StringIndexOfChar, 0),
                _ => throw new NotSupportedException("Unsupported string intrinsic.")
            };
        }
        int local = i.OpCode.Code switch {
            Code.Stloc_0 => 0, Code.Stloc_1 => 1, Code.Stloc_2 => 2, Code.Stloc_3 => 3,
            Code.Stloc or Code.Stloc_S => ((VariableDefinition)i.Operand).Index, _ => -1 };
        if (local >= 0)
        {
            var type = method.Body.Variables[local].VariableType.MetadataType;
            return (type == MetadataType.Char ? O.StoreCharLocal : type == MetadataType.Boolean ? O.StoreBoolLocal : O.StoreLocal, local);
        }
        int target = i.Operand is Instruction t ? indices[t] : 0;
        return i.OpCode.Code switch
        {
            Code.Nop => (O.Nop,0),
            Code.Conv_U2 => (O.ConvertU2,0),
            Code.Ldnull => (O.Constant,0),
            Code.Ldc_I4_M1 => (O.Constant,-1),
            Code.Ldc_I4_0 => (O.Constant,0), Code.Ldc_I4_1 => (O.Constant,1),
            Code.Ldc_I4_2 => (O.Constant,2), Code.Ldc_I4_3 => (O.Constant,3),
            Code.Ldc_I4_4 => (O.Constant,4), Code.Ldc_I4_5 => (O.Constant,5),
            Code.Ldc_I4_6 => (O.Constant,6), Code.Ldc_I4_7 => (O.Constant,7),
            Code.Ldc_I4_8 => (O.Constant,8), Code.Ldc_I4_S => (O.Constant,(sbyte)i.Operand),
            Code.Ldc_I4 => (O.Constant,(int)i.Operand),
            Code.Ldarg_0 => (O.Argument,0), Code.Ldarg_1 => (O.Argument,1),
            Code.Ldarg_2 => (O.Argument,2), Code.Ldarg_3 => (O.Argument,3),
            Code.Ldarg or Code.Ldarg_S => (O.Argument,((ParameterDefinition)i.Operand).Index),
            Code.Ldloc_0 => (O.LoadLocal,0), Code.Ldloc_1 => (O.LoadLocal,1),
            Code.Ldloc_2 => (O.LoadLocal,2), Code.Ldloc_3 => (O.LoadLocal,3),
            Code.Ldloc or Code.Ldloc_S => (O.LoadLocal,((VariableDefinition)i.Operand).Index),
            Code.Stloc_0 => (O.StoreLocal,0), Code.Stloc_1 => (O.StoreLocal,1),
            Code.Stloc_2 => (O.StoreLocal,2), Code.Stloc_3 => (O.StoreLocal,3),
            Code.Stloc or Code.Stloc_S => (O.StoreLocal,((VariableDefinition)i.Operand).Index),
            Code.Dup => (O.Dup,0), Code.Pop => (O.Pop,0),
            Code.Add => (O.Add,0), Code.Sub => (O.Sub,0), Code.Mul => (O.Mul,0),
            Code.Div => (O.Div,0), Code.Rem => (O.Rem,0),
            Code.Div_Un => (O.DivUnsigned,0), Code.Rem_Un => (O.RemUnsigned,0),
            Code.And => (O.And,0), Code.Or => (O.Or,0), Code.Xor => (O.Xor,0),
            Code.Shl => (O.Shl,0), Code.Shr => (O.Shr,0), Code.Shr_Un => (O.ShrUnsigned,0),
            Code.Neg => (O.Neg,0), Code.Not => (O.Not,0),
            Code.Ceq => (O.Equal,0), Code.Cgt => (O.Greater,0), Code.Clt => (O.Less,0),
            Code.Cgt_Un => (O.GreaterUnsigned,0), Code.Clt_Un => (O.LessUnsigned,0),
            Code.Br or Code.Br_S => (O.Jump,target),
            Code.Brfalse or Code.Brfalse_S => (O.False,target),
            Code.Brtrue or Code.Brtrue_S => (O.True,target),
            Code.Beq or Code.Beq_S => (O.Eq,target),
            Code.Bne_Un or Code.Bne_Un_S => (O.Ne,target),
            Code.Bge or Code.Bge_S => (O.Ge,target), Code.Bgt or Code.Bgt_S => (O.Gt,target),
            Code.Ble or Code.Ble_S => (O.Le,target), Code.Blt or Code.Blt_S => (O.Lt,target),
            Code.Bge_Un or Code.Bge_Un_S => (O.GeUnsigned,target),
            Code.Bgt_Un or Code.Bgt_Un_S => (O.GtUnsigned,target),
            Code.Ble_Un or Code.Ble_Un_S => (O.LeUnsigned,target),
            Code.Blt_Un or Code.Blt_Un_S => (O.LtUnsigned,target),
            Code.Add_Ovf => (O.AddChecked,0), Code.Sub_Ovf => (O.SubChecked,0), Code.Mul_Ovf => (O.MulChecked,0),
            Code.Add_Ovf_Un => (O.AddCheckedUnsigned,0), Code.Sub_Ovf_Un => (O.SubCheckedUnsigned,0),
            Code.Mul_Ovf_Un => (O.MulCheckedUnsigned,0),
            Code.Ret => (O.Return,0),
            _ => throw new NotSupportedException("Unsupported VM opcode: " + i.OpCode)
        };
    }
}
