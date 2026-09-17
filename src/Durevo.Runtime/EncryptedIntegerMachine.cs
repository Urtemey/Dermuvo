using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Durevo.Runtime;

/// <summary>Encrypted VM transport. Key provisioning/licensing is a separate trusted-host responsibility.</summary>
public static class EncryptedIntegerMachine
{
    public const int MaximumWords = 262144;
    public const int MaximumEnvelopeBytes = 36 + 24 + MaximumWords * 4;
    private static readonly byte[] Domain = Encoding.ASCII.GetBytes("DUR-EVM1");
    private static readonly object Gate = new object();
    private static readonly Dictionary<string, KeyLease> Keys = new Dictionary<string, KeyLease>(StringComparer.Ordinal);

    public static string IdentifyKey(byte[] key)
    {
        if (key is null || key.Length != 32) throw new ArgumentException("A random 256-bit program key is required.");
        using var sha = SHA256.Create();
        return Convert.ToBase64String(sha.ComputeHash(key));
    }

    public static byte[] AssociatedData(string keyId, string context)
    {
        if (context is null || context.Length == 0 || context.Length > 4096 || keyId is null || keyId.Length != 44)
            throw new ArgumentException("Invalid program context/key identity size.");
        byte[] identity = Convert.FromBase64String(keyId);
        byte[] text = new UTF8Encoding(false, true).GetBytes(context);
        if (identity.Length != 32 || text.Length == 0 || text.Length > 4096)
            throw new ArgumentException("Invalid program context/key identity.");
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(Domain); writer.Write(identity); writer.Write(text.Length); writer.Write(text);
        return stream.ToArray();
    }

    public static KeyLease RegisterKey(byte[] key) => Register(key, null, 0, 0, false);
    public static KeyLease RegisterNativeKey(byte[] key) => Register(key, null, 0, 0, true);

    public static KeyLease RegisterVerifiedNativeKey(byte[] key, VerifiedNativeBackend backend) =>
        Register(key, null, 0, 0, true, backend ?? throw new ArgumentNullException(nameof(backend)));

    internal static KeyLease RegisterLicensedKey(byte[] key, long notBefore, long expires, Func<DateTimeOffset> clock, bool native = false, VerifiedNativeBackend? backend = null) =>
        Register(key, clock, notBefore, expires, native, backend);

    private static KeyLease Register(byte[] key, Func<DateTimeOffset>? clock, long notBefore, long expires, bool native, VerifiedNativeBackend? backend = null)
    {
        if (key is null || key.Length != 32) throw new ArgumentException("Expected a 256-bit key.");
        var lease = new KeyLease(key, clock, notBefore, expires, native, backend);
        lock (Gate)
        {
            if (Keys.ContainsKey(lease.KeyId))
            {
                lease.NativeHandle?.Dispose();
                Array.Clear(lease.Bytes, 0, lease.Bytes.Length);
                throw new InvalidOperationException("Program key already registered.");
            }
            Keys.Add(lease.KeyId, lease);
        }
        return lease;
    }

    public sealed class KeyLease : IDisposable
    {
        internal byte[] Bytes { get; }
        internal NativeEncryptedExecution.KeyHandle? NativeHandle { get; }
        public string KeyId { get; }
        private bool disposed;
        private readonly Func<DateTimeOffset>? clock;
        private readonly long notBefore, expires;
        internal KeyLease(byte[] bytes, Func<DateTimeOffset>? clock, long notBefore, long expires, bool native, VerifiedNativeBackend? backend)
        {
            KeyId = IdentifyKey(bytes); this.clock = clock; this.notBefore = notBefore; this.expires = expires;
            Bytes = native ? Array.Empty<byte>() : (byte[])bytes.Clone();
            if (native) NativeHandle = NativeEncryptedExecution.Import(bytes, backend);
        }
        internal void CheckValidity()
        {
            if (clock == null) return; // Explicit low-level provisioning, no license policy claimed.
            long now = clock().ToUnixTimeSeconds();
            if (now < notBefore || now >= expires)
            {
                Dispose();
                throw new UnauthorizedAccessException("Program-key license is not currently valid.");
            }
        }
        public void Dispose()
        {
            lock (Gate)
            {
                if (disposed) return;
                disposed = true;
                Keys.Remove(KeyId);
                NativeHandle?.Dispose();
                Array.Clear(Bytes, 0, Bytes.Length);
            }
        }
    }

    public static int Run(string encodedEnvelope, string keyId, string context, int[] arguments) =>
        RunCore(encodedEnvelope, keyId, context, arguments, false, Array.Empty<string>());
    public static int RunNative(string encodedEnvelope, string keyId, string context, int[] arguments) =>
        RunCore(encodedEnvelope, keyId, context, arguments, true, Array.Empty<string>());

    public static int RunStrings(string encodedEnvelope, string keyId, string context, int[] arguments, string[] strings) =>
        RunCore(encodedEnvelope, keyId, context, arguments, false, strings);
    public static int RunNativeStrings(string encodedEnvelope, string keyId, string context, int[] arguments, string[] strings) =>
        RunCore(encodedEnvelope, keyId, context, arguments, true, strings);

    public static int RunVerifiedNative(string envelope, string keyId, string context, int[] arguments) =>
        RunCore(envelope, keyId, context, arguments, true, Array.Empty<string>(), true);
    public static int RunVerifiedNativeStrings(string envelope, string keyId, string context, int[] arguments, string[] strings) =>
        RunCore(envelope, keyId, context, arguments, true, strings, true);

    private static int RunCore(string encodedEnvelope, string keyId, string context, int[] arguments, bool requireNative, string[] strings, bool requireVerified = false)
    {
        if (encodedEnvelope is null || encodedEnvelope.Length > ((MaximumEnvelopeBytes + 2) / 3) * 4 ||
            arguments is null || arguments.Length > 65536 || strings is null || strings.Length > 65536)
            throw new ArgumentException("Encrypted program input exceeds limits.");
        byte[] envelope = Convert.FromBase64String(encodedEnvelope);
        if (envelope.Length < 36 + 24 + 8 || envelope.Length > MaximumEnvelopeBytes)
            throw new InvalidDataException("Invalid encrypted program size.");
        for (int i = 0; i < Domain.Length; i++)
            if (envelope[i] != Domain[i]) throw new InvalidDataException("Wrong encrypted program domain.");
        byte[] aad = AssociatedData(keyId, context);
        KeyLease active;
        lock (Gate)
        {
            if (!Keys.TryGetValue(keyId, out active!))
                throw new UnauthorizedAccessException("The program decryption key has not been provisioned.");
        }
        active.CheckValidity(); // Invoke the trusted clock outside the registry lock.
        byte[] key;
        NativeEncryptedExecution.KeyHandle? nativeHandle;
        lock (Gate)
        {
            if (!Keys.TryGetValue(keyId, out var current) || !ReferenceEquals(active, current))
                throw new UnauthorizedAccessException("The program key was revoked while authorizing execution.");
            nativeHandle = active.NativeHandle;
            if (requireVerified && nativeHandle?.Owner == null)
                throw new UnauthorizedAccessException("This program requires a verified native backend.");
            if (requireNative && nativeHandle == null)
                throw new UnauthorizedAccessException("Native encrypted execution requires a native key lease.");
            key = nativeHandle == null ? (byte[])active.Bytes.Clone() : Array.Empty<byte>();
        }
        if (nativeHandle != null) return NativeEncryptedExecution.Run(nativeHandle, envelope, aad, arguments, strings);
        byte[] plaintext = new byte[envelope.Length - 36];
        int[]? program = null;
        try
        {
            var nonce = new byte[12];
            Array.Copy(envelope, 8, nonce, 0, 12);
            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce, aad));
            int count;
            try
            {
                count = cipher.ProcessBytes(envelope, 20, envelope.Length - 20, plaintext, 0);
                count += cipher.DoFinal(plaintext, count);
            }
            catch (InvalidCipherTextException error)
            { throw new CryptographicException("Encrypted program authentication failed.", error); }
            if (count != plaintext.Length) throw new CryptographicException("Unexpected decrypted size.");
            // No program metadata or instruction is used before successful tag verification.
            using var reader = new BinaryReader(new MemoryStream(plaintext, false));
            int native = reader.ReadInt32(), locals = reader.ReadInt32(), stack = reader.ReadInt32();
            int argumentsExpected = reader.ReadInt32(), xorKey = reader.ReadInt32(), words = reader.ReadInt32();
            if ((native != 0 && native != 1) || locals < 0 || locals > 65536 || stack < 1 || stack > 65536 ||
                argumentsExpected != arguments.Length || words < 2 || words > MaximumWords ||
                (words & 1) != 0 || plaintext.Length != 24 + words * 4)
                throw new InvalidDataException("Invalid authenticated VM metadata.");
            program = new int[words];
            for (int i = 0; i < words; i++) program[i] = reader.ReadInt32();
            return native == 1
                ? NativeIntegerMachine.RunStrings(program, arguments, locals, stack, xorKey, strings)
                : IntegerMachine.RunStrings(program, arguments, locals, stack, xorKey, strings);
        }
        finally
        {
            Array.Clear(key, 0, key.Length);
            Array.Clear(plaintext, 0, plaintext.Length);
            if (program != null) Array.Clear(program, 0, program.Length);
        }
    }
}
