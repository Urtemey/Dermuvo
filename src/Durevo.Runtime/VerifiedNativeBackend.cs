using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
namespace Durevo.Runtime;

// Exact-handle dispatch for a signed byte snapshot. Does not authenticate OS dependencies or prevent in-process patches.
public sealed class VerifiedNativeBackend : IDisposable
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Create([In] byte[] key, uint length, out IntPtr handle);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void Destroy(IntPtr handle);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Execute(IntPtr handle, [In] byte[] envelope, uint length,
        [In] byte[] aad, uint aadLength, [In] int[] args, uint argc, ulong budget, out int result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int ExecuteStrings(IntPtr handle, [In] byte[] envelope, uint length,
        [In] byte[] aad, uint aadLength, [In] int[] args, uint argc, [In] IntPtr[] strings, [In] int[] lengths, uint count, ulong budget, out int result);
    private readonly object gate = new object();
    private bool disposed;
    private readonly ModuleHandle module;
    private readonly Create create;
    private readonly Destroy destroy;
    private readonly Execute execute;
    private readonly ExecuteStrings executeStrings;
    public string Product { get; }
    public ulong Revision { get; }
    private VerifiedNativeBackend(ModuleHandle module, string product, ulong revision)
    {
        this.module = module; Product = product; Revision = revision;
        create = Resolve<Create>("durevo_key_create");
        destroy = Resolve<Destroy>("durevo_key_destroy");
        execute = Resolve<Execute>("durevo_run_encrypted");
        executeStrings = Resolve<ExecuteStrings>("durevo_run_encrypted_strings");
    }
    private T Resolve<T>(string name) where T : Delegate
    {
        IntPtr address = module.Windows ? GetProcAddress(module.DangerousGetHandle(), name) : dlsym(module.DangerousGetHandle(), name);
        if (address == IntPtr.Zero) throw new EntryPointNotFoundException("Verified backend is missing " + name);
        return Marshal.GetDelegateForFunctionPointer<T>(address);
    }
    internal static VerifiedNativeBackend LoadSnapshot(byte[] bytes, string product, ulong revision)
    {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("Verified native binding requires a 64-bit process.");
        ModuleHandle handle = LoadModule(bytes);
        try { return new VerifiedNativeBackend(handle, product, revision); }
        catch { handle.Dispose(); throw; }
    }
    internal NativeEncryptedExecution.KeyHandle Import(byte[] key)
    {
        bool retained = false;
        IntPtr pointer = IntPtr.Zero;
        try {
            lock (gate) {
                if (disposed) throw new ObjectDisposedException(nameof(VerifiedNativeBackend));
                module.DangerousAddRef(ref retained);
            }
            int status = create(key, (uint)key.Length, out pointer);
            if (status != 0) NativeEncryptedExecution.Throw(status);
            if (pointer == IntPtr.Zero) throw new CryptographicException("Verified native key import returned no handle.");
            var result = new NativeEncryptedExecution.KeyHandle(pointer, this);
            pointer = IntPtr.Zero; retained = false; // Key handle owns this module reference.
            return result;
        }
        finally {
            if (pointer != IntPtr.Zero) destroy(pointer);
            if (retained) module.DangerousRelease();
        }
    }
    internal void ReleaseKey(IntPtr key)
    {
        try { destroy(key); }
        finally { module.DangerousRelease(); }
    }
    internal int Run(NativeEncryptedExecution.KeyHandle key, byte[] envelope, byte[] aad, int[] args, string[] strings)
    {
        bool retained = false;
        try {
            key.DangerousAddRef(ref retained);
            int status, result;
            if (strings.Length == 0)
                status = execute(key.DangerousGetHandle(), envelope, (uint)envelope.Length, aad, (uint)aad.Length, args, (uint)args.Length, ulong.MaxValue, out result);
            else {
                using var pinned = new NativeStringArguments(strings);
                status = executeStrings(key.DangerousGetHandle(), envelope, (uint)envelope.Length, aad, (uint)aad.Length,
                    args, (uint)args.Length, pinned.Pointers, pinned.Lengths, (uint)strings.Length, ulong.MaxValue, out result);
            }
            if (status != 0) NativeEncryptedExecution.Throw(status);
            return result;
        }
        catch (ObjectDisposedException) { throw new UnauthorizedAccessException("Verified native key lease was disposed."); }
        finally { if (retained) key.DangerousRelease(); }
    }
    // Existing key leases retain the module; disposing this factory only prevents new imports.
    public void Dispose()
    {
        lock (gate) {
            if (disposed) return;
            disposed = true;
            module.Dispose();
        }
    }

    private sealed class ModuleHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal readonly bool Windows;
        private readonly int descriptor;
        private readonly FileStream? file;
        private readonly string? directory, path;
        internal ModuleHandle(IntPtr handle, bool windows, int descriptor, FileStream? file, string? directory, string? path) : base(true)
        { SetHandle(handle); Windows = windows; this.descriptor = descriptor; this.file = file; this.directory = directory; this.path = path; }
        protected override bool ReleaseHandle()
        {
            bool result = Windows ? FreeLibrary(handle) : dlclose(handle) == 0;
            file?.Dispose();
            if (descriptor >= 0) close(descriptor);
            Cleanup(directory, path);
            return result;
        }
    }
    private static void Cleanup(string? directory, string? path)
    {
        if (path == null || directory == null) return;
        try { File.Delete(path); Directory.Delete(directory); }
        catch (IOException) { } catch (UnauthorizedAccessException) { } // Best-effort removal of this unique non-secret DLL copy.
    }
    private static ModuleHandle LoadModule(byte[] bytes)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            string directory = Path.Combine(Path.GetTempPath(), "durevo-native-" + Guid.NewGuid().ToString("N"));
            string path = Path.Combine(directory, "backend-" + Guid.NewGuid().ToString("N") + ".dll");
            Directory.CreateDirectory(directory);
            FileStream? file = null;
            IntPtr loaded = IntPtr.Zero;
            try {
                using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { output.Write(bytes, 0, bytes.Length); output.Flush(true); }
                file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                using (var sha = SHA256.Create())
                    if (!CryptographicOperations.FixedTimeEquals(sha.ComputeHash(file), sha.ComputeHash(bytes))) throw new CryptographicException("Native copy changed.");
                if (GetModuleHandleW(path) != IntPtr.Zero) throw new InvalidOperationException("Native snapshot path was already loaded.");
                loaded = LoadLibraryExW(path, IntPtr.Zero, 0x00000800); // Dependencies only from System32.
                if (loaded == IntPtr.Zero) throw new DllNotFoundException("Verified native load failed: Win32 " + Marshal.GetLastWin32Error());
                return new ModuleHandle(loaded, true, -1, file, directory, path);
            }
            catch {
                if (loaded != IntPtr.Zero) FreeLibrary(loaded);
                file?.Dispose(); Cleanup(directory, path); throw;
            }
        }
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) throw new PlatformNotSupportedException("Verified native binding supports Windows/Linux.");
        int fd = memfd_create("durevo-native", 3); // CLOEXEC | ALLOW_SEALING.
        if (fd < 0) throw new IOException("Unable to allocate sealed native image: errno " + Marshal.GetLastWin32Error());
        IntPtr module = IntPtr.Zero;
        try {
            var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try {
                int offset = 0;
                while (offset < bytes.Length) {
                    long written = write(fd, IntPtr.Add(pinned.AddrOfPinnedObject(), offset), new UIntPtr((uint)(bytes.Length - offset))).ToInt64();
                    if (written < 0 && Marshal.GetLastWin32Error() == 4) continue; // EINTR.
                    if (written <= 0 || written > bytes.Length - offset) throw new IOException("Failed to write native image.");
                    offset += (int)written;
                }
            } finally { pinned.Free(); }
            if (fcntl(fd, 1033, 15) != 0 || (fcntl(fd, 1034, 0) & 15) != 15)
                throw new IOException("Native image could not be sealed.");
            module = dlopen("/proc/self/fd/" + fd, 2); // RTLD_NOW | RTLD_LOCAL.
            if (module == IntPtr.Zero) throw new DllNotFoundException("Unable to load sealed native image or its dependencies.");
            return new ModuleHandle(module, false, fd, null, null, null);
        }
        catch { if (module != IntPtr.Zero) dlclose(module); close(fd); throw; }
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)] private static extern IntPtr LoadLibraryExW(string path, IntPtr reserved, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern IntPtr GetModuleHandleW(string path);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)] private static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll", ExactSpelling = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool FreeLibrary(IntPtr module);
    [DllImport("libc.so.6", SetLastError = true)] private static extern int memfd_create(string name, uint flags);
    [DllImport("libc.so.6", SetLastError = true)] private static extern IntPtr write(int fd, IntPtr bytes, UIntPtr count);
    [DllImport("libc.so.6", SetLastError = true)] private static extern int fcntl(int fd, int command, int argument);
    [DllImport("libc.so.6")] private static extern int close(int fd);
    [DllImport("libdl.so.2")] private static extern IntPtr dlopen(string path, int flags);
    [DllImport("libdl.so.2")] private static extern IntPtr dlsym(IntPtr module, string name);
    [DllImport("libdl.so.2")] private static extern int dlclose(IntPtr module);
}
