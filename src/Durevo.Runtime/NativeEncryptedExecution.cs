using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Durevo.Runtime;

// Internal bridge: no plaintext/program/key export API. Native memory is still debugger-readable.
internal static class NativeEncryptedExecution
{
    [DllImport("durevo_vm", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int durevo_key_create([In] byte[] key, uint length, out KeyHandle handle);
    [DllImport("durevo_vm", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void durevo_key_destroy(IntPtr handle);
    [DllImport("durevo_vm", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int durevo_run_encrypted(KeyHandle handle, [In] byte[] envelope, uint envelopeLength,
        [In] byte[] aad, uint aadLength, [In] int[] arguments, uint argc, ulong steps, out int result);

    [DllImport("durevo_vm", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int durevo_run_encrypted_strings(KeyHandle handle, [In] byte[] envelope, uint envelopeLength,
        [In] byte[] aad, uint aadLength, [In] int[] arguments, uint argc, [In] IntPtr[] strings,
        [In] int[] lengths, uint stringCount, ulong steps, out int result);

    internal sealed class KeyHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal VerifiedNativeBackend? Owner { get; }
        public KeyHandle() : base(true) { }
        internal KeyHandle(IntPtr pointer, VerifiedNativeBackend owner) : base(true) { SetHandle(pointer); Owner = owner; }
        protected override bool ReleaseHandle() { if (Owner != null) Owner.ReleaseKey(handle); else durevo_key_destroy(handle); return true; }
    }
    internal static KeyHandle Import(byte[] key, VerifiedNativeBackend? backend = null)
    {
        if (backend != null) return backend.Import(key);
        int status = durevo_key_create(key, (uint)key.Length, out var handle);
        if (status != 0) { handle?.Dispose(); Throw(status); }
        if (handle == null || handle.IsInvalid) throw new CryptographicException("Native key import returned no handle.");
        return handle;
    }
    internal static int Run(KeyHandle handle, byte[] envelope, byte[] aad, int[] arguments, string[] strings)
    {
        if (handle.Owner != null) return handle.Owner.Run(handle, envelope, aad, arguments, strings);
        int status;
        int result;
        try
        {
            if (strings.Length == 0)
                status = durevo_run_encrypted(handle, envelope, (uint)envelope.Length, aad, (uint)aad.Length,
                    arguments, (uint)arguments.Length, ulong.MaxValue, out result);
            else
            {
                using var input = new NativeStringArguments(strings);
                status = durevo_run_encrypted_strings(handle, envelope, (uint)envelope.Length, aad, (uint)aad.Length,
                    arguments, (uint)arguments.Length, input.Pointers, input.Lengths, (uint)strings.Length, ulong.MaxValue, out result);
            }
        }
        catch (ObjectDisposedException) { throw new UnauthorizedAccessException("Native key lease was disposed."); }
        if (status != 0) Throw(status);
        return result;
    }
    internal static void Throw(int status)
    {
        switch (status)
        {
            case 1: throw new InvalidDataException("Invalid native encrypted program.");
            case 2: throw new DivideByZeroException();
            case 3: throw new OverflowException();
            case 4: throw new OutOfMemoryException();
            case 5: throw new TimeoutException("Native VM budget exhausted.");
            case 8: throw new NullReferenceException();
            case 9: throw new IndexOutOfRangeException();
            case 6: throw new CryptographicException("Encrypted program authentication failed.");
            default: throw new CryptographicException("Native crypto provider failed.");
        }
    }
}
