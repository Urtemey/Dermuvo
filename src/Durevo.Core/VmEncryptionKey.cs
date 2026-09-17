using System.Security.Cryptography;
using System.Text;
using Durevo.Runtime;

namespace Durevo.Core;

/// <summary>Build-side encryption authority; never serialize this key into protected output.</summary>
public sealed class VmEncryptionKey : IDisposable
{
    private readonly byte[] key;
    private readonly object gate = new();
    private bool disposed;
    public string KeyId { get; }
    public VmEncryptionKey(byte[] bytes)
    {
        if (bytes is null || bytes.Length != 32) throw new ArgumentException("Expected 32 random key bytes.");
        key = (byte[])bytes.Clone();
        KeyId = EncryptedIntegerMachine.IdentifyKey(key);
    }

    public string Seal(int[] words, int locals, int stack, int arguments, int xorKey, bool native, string context)
    {
        lock (gate) return SealCore(words, locals, stack, arguments, xorKey, native, context);
    }

    private string SealCore(int[] words, int locals, int stack, int arguments, int xorKey, bool native, string context)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (words.Length < 2 || words.Length > EncryptedIntegerMachine.MaximumWords || (words.Length & 1) != 0)
            throw new ArgumentException("Program word count exceeds encrypted VM limits.");
        byte[] payload = new byte[24 + words.Length * 4];
        try
        {
            using (var writer = new BinaryWriter(new MemoryStream(payload, true)))
            {
                writer.Write(native ? 1 : 0); writer.Write(locals); writer.Write(stack);
                writer.Write(arguments); writer.Write(xorKey); writer.Write(words.Length);
                foreach (int word in words) writer.Write(word);
            }
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] envelope = new byte[payload.Length + 36];
            Encoding.ASCII.GetBytes("DUR-EVM1").CopyTo(envelope, 0);
            nonce.CopyTo(envelope, 8);
            using var cipher = new AesGcm(key, 16);
            cipher.Encrypt(nonce, payload, envelope.AsSpan(20, payload.Length),
                envelope.AsSpan(20 + payload.Length, 16), EncryptedIntegerMachine.AssociatedData(KeyId, context));
            return Convert.ToBase64String(envelope);
        }
        finally { CryptographicOperations.ZeroMemory(payload); }
    }
    public void Dispose()
    {
        lock (gate)
        {
        if (disposed) return;
        disposed = true;
        CryptographicOperations.ZeroMemory(key);
        }
    }
}
