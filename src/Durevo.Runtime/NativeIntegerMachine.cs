using System;
using System.Runtime.InteropServices;
namespace Durevo.Runtime;

public static class NativeIntegerMachine
{
    [DllImport("durevo_vm", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int durevo_run([In] int[] program, uint length, [In] int[] arguments,
        uint argumentCount, uint localCount, uint stackSize, uint key, ulong steps, out int result);

    [DllImport("durevo_vm", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int durevo_run_strings([In] int[] program, uint length, [In] int[] arguments,
        uint argumentCount, uint localCount, uint stackSize, uint key, [In] IntPtr[] strings,
        [In] int[] lengths, uint stringCount, ulong steps, out int result);

    public static int RunStrings(int[] program, int[] arguments, int localCount, int stackSize, int key, string[] strings)
    {
        if (program is null || arguments is null) throw new ArgumentNullException();
        if (localCount < 0 || stackSize < 1) throw new ArgumentOutOfRangeException();
        using var input = new NativeStringArguments(strings);
        int status = durevo_run_strings(program, (uint)program.Length, arguments, (uint)arguments.Length,
            (uint)localCount, (uint)stackSize, unchecked((uint)key), input.Pointers, input.Lengths,
            (uint)strings.Length, ulong.MaxValue, out int result);
        return Result(status, result);
    }

    public static int Run(int[] program, int[] arguments, int localCount, int stackSize, int key) =>
        RunWithBudget(program, arguments, localCount, stackSize, key, ulong.MaxValue);

    // Budget is explicit. The normal compiler-generated entry does not impose a practical step limit.
    public static int RunWithBudget(int[] program, int[] arguments, int localCount, int stackSize, int key, ulong steps)
    {
        if (program is null || arguments is null) throw new ArgumentNullException();
        if (localCount < 0 || stackSize < 1) throw new ArgumentOutOfRangeException();
        int status = durevo_run(program, (uint)program.Length, arguments, (uint)arguments.Length,
            (uint)localCount, (uint)stackSize, unchecked((uint)key), steps, out int result);
        return Result(status, result);
    }
    private static int Result(int status, int result)
    {
        switch(status)
        {
            case 0: return result;
            case 2: throw new DivideByZeroException();
            case 3: throw new OverflowException();
            case 4: throw new OutOfMemoryException();
            case 8: throw new NullReferenceException();
            case 9: throw new IndexOutOfRangeException();
            case 5: throw new TimeoutException("Durevo VM step budget exhausted.");
            default: throw new InvalidOperationException("Invalid Durevo native program.");
        }
    }
}
