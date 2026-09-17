using Mono.Cecil;
using Mono.Cecil.Cil;

// Adaptive static probe: string concealment is not a security boundary.
// Recovers envelope/context without running the target; decryption still needs the external key.
internal static class EncryptedRecoveryProbe
{
    internal static (string Envelope, string KeyId, string Context) Extract(MethodDefinition method)
    {
        var stack = new Stack<object>();
        var instructions = method.Body.Instructions;
        for (int pc = 0, steps = 0; pc < instructions.Count && steps++ < 100000; pc++)
        {
            var instruction = instructions[pc];
            switch (instruction.OpCode.Code)
            {
                case Code.Ldstr: stack.Push((string)instruction.Operand); break;
                case Code.Ldc_I4: stack.Push((int)instruction.Operand); break;
                case Code.Xor: { int b = (int)stack.Pop(), a = (int)stack.Pop(); stack.Push(a ^ b); break; }
                case Code.Newarr: stack.Push(new int[(int)stack.Pop()]); break;
                case Code.Dup: stack.Push(stack.Peek()); break;
                case Code.Stelem_I4:
                    { int value = (int)stack.Pop(), index = (int)stack.Pop(); ((int[])stack.Pop())[index] = value; break; }
                case Code.Ldarg: case Code.Ldarg_S:
                case Code.Ldarg_0: case Code.Ldarg_1: case Code.Ldarg_2: case Code.Ldarg_3:
                    stack.Push(0); break;
                case Code.Br: case Code.Br_S: pc = instructions.IndexOf((Instruction)instruction.Operand) - 1; break;
                case Code.Call:
                {
                    var target = (MethodReference)instruction.Operand;
                    if (target.Name == "Decode" && target.Parameters.Count == 2)
                    {
                        int key = (int)stack.Pop();
                        byte[] bytes = Convert.FromBase64String((string)stack.Pop());
                        char[] chars = new char[bytes.Length / 2];
                        for (int i = 0; i < chars.Length; i++) chars[i] = (char)((bytes[2*i] | bytes[2*i+1] << 8) ^ key);
                        stack.Push(new string(chars));
                    }
                    else if (target.DeclaringType.FullName == "Durevo.Runtime.EncryptedIntegerMachine")
                    {
                        stack.Pop();
                        string context = (string)stack.Pop(), keyId = (string)stack.Pop(), envelope = (string)stack.Pop();
                        return (envelope, keyId, context);
                    }
                    else throw new InvalidOperationException("Unrecognized call in adaptive probe.");
                    break;
                }
                default: throw new InvalidOperationException("Adapt probe for " + instruction.OpCode);
            }
        }
        throw new InvalidOperationException("No encrypted VM entry.");
    }
}
