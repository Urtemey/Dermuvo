using System;
using System.Runtime.InteropServices;
namespace Durevo.Runtime;

// Pins only caller input text, never protected program bytes. Preserves UTF-16 including embedded NUL.
internal sealed class NativeStringArguments : IDisposable
{
    internal IntPtr[] Pointers { get; }
    internal int[] Lengths { get; }
    private readonly GCHandle[] pins;
    internal NativeStringArguments(string[] strings)
    {
        if (strings == null || strings.Length > 65536) throw new ArgumentException("Invalid string arguments.");
        Pointers = new IntPtr[strings.Length]; Lengths = new int[strings.Length]; pins = new GCHandle[strings.Length];
        try
        {
            for (int i = 0; i < strings.Length; i++)
            {
                string text = strings[i];
                if (text == null) { Lengths[i] = -1; continue; }
                Lengths[i] = text.Length;
                pins[i] = GCHandle.Alloc(text, GCHandleType.Pinned);
                Pointers[i] = pins[i].AddrOfPinnedObject();
            }
        }
        catch { Dispose(); throw; }
    }
    public void Dispose()
    {
        for (int i = 0; i < pins.Length; i++)
        {
            if (pins[i].IsAllocated) pins[i].Free();
            Pointers[i] = IntPtr.Zero;
        }
    }
}
