using Mono.Cecil;
using Mono.Cecil.Cil;

// Deliberately independent adversarial probe: recover a VM payload statically from
// the protected wrapper, without running target code or reading compiler internals.
internal static class RecoveryProbe
{
    public static int[] Recover(MethodDefinition method)
    {
        var stack = new Stack<object>();
        foreach (var i in method.Body.Instructions)
        {
            switch(i.OpCode.Code)
            {
                case Code.Ldc_I4: stack.Push((int)i.Operand); break;
                case Code.Xor: { int b=(int)stack.Pop(), a=(int)stack.Pop(); stack.Push(a^b); break; }
                case Code.Newarr: stack.Push(new int[(int)stack.Pop()]); break;
                case Code.Dup: stack.Push(stack.Peek()); break;
                case Code.Stelem_I4:
                {
                    int value=(int)stack.Pop(), index=(int)stack.Pop();
                    ((int[])stack.Pop())[index]=value; break;
                }
                case Code.Ldarg: case Code.Ldarg_S:
                case Code.Ldarg_0: case Code.Ldarg_1: case Code.Ldarg_2: case Code.Ldarg_3:
                    stack.Push(0); break; // Actual argument values do not affect the embedded program.
                case Code.Call when ((MethodReference)i.Operand).DeclaringType.FullName is "Durevo.Runtime.IntegerMachine" or "Durevo.Runtime.NativeIntegerMachine":
                {
                    int key=(int)stack.Pop();
                    stack.Pop(); stack.Pop(); stack.Pop();
                    var code=(int[])stack.Pop();
                    for(int j=0;j<code.Length;j++) code[j] ^= unchecked(key+j*(int)0x9e3779b9);
                    return code;
                }
                default: throw new InvalidOperationException("Probe needs adaptation for: "+i.OpCode);
            }
        }
        throw new InvalidOperationException("VM entry not found.");
    }
}
