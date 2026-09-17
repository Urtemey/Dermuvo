using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Durevo.Runtime;

// A grant authenticates the association of one exact license ticket and one program key.
// It contains NO program key. Confidential key delivery remains a separate requirement.
public static class ProgramKeyGrant
{
    public const int GrantBytes = 144;
    private static readonly byte[] Domain = Encoding.ASCII.GetBytes("DUR-KGR1");

    public static byte[] EncodeBinding(byte[] license, byte[] programKey, ulong keyFeatures)
    {
        if (license is null || license.Length < 72 || license.Length > OfflineLicense.MaximumTicketBytes)
            throw new ArgumentException("Invalid license ticket size.");
        if (programKey is null || programKey.Length != 32) throw new ArgumentException("Expected 32-byte program key.");
        using var sha = SHA256.Create();
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(Domain); writer.Write(sha.ComputeHash(license)); writer.Write(sha.ComputeHash(programKey));
        writer.Write(keyFeatures);
        return stream.ToArray();
    }

    public static EncryptedIntegerMachine.KeyLease Activate(byte[] grant, byte[] license, byte[] programKey,
        byte[] trustedPublicKey, string expectedKeyId, string expectedProduct, string expectedDevice,
        ulong requiredFeatures, uint requestedSeats, Func<DateTimeOffset> clock) =>
        ActivateCore(grant, license, programKey, trustedPublicKey, expectedKeyId, expectedProduct,
            expectedDevice, requiredFeatures, requestedSeats, clock, false);

    public static EncryptedIntegerMachine.KeyLease ActivateNative(byte[] grant, byte[] license, byte[] programKey,
        byte[] trustedPublicKey, string expectedKeyId, string expectedProduct, string expectedDevice,
        ulong requiredFeatures, uint requestedSeats, Func<DateTimeOffset> clock) =>
        ActivateCore(grant, license, programKey, trustedPublicKey, expectedKeyId, expectedProduct,
            expectedDevice, requiredFeatures, requestedSeats, clock, true);

    public static EncryptedIntegerMachine.KeyLease ActivateVerifiedNative(byte[] grant, byte[] license, byte[] programKey,
        byte[] trustedPublicKey, string expectedKeyId, string expectedProduct, string expectedDevice,
        ulong requiredFeatures, uint requestedSeats, Func<DateTimeOffset> clock, VerifiedNativeBackend backend)
    {
        if (backend == null || backend.Product != expectedProduct) throw new UnauthorizedAccessException("Native backend product mismatch.");
        return ActivateCore(grant, license, programKey, trustedPublicKey, expectedKeyId, expectedProduct, expectedDevice,
            requiredFeatures, requestedSeats, clock, true, backend);
    }

    private static EncryptedIntegerMachine.KeyLease ActivateCore(byte[] grant, byte[] license, byte[] programKey,
        byte[] trustedPublicKey, string expectedKeyId, string expectedProduct, string expectedDevice,
        ulong requiredFeatures, uint requestedSeats, Func<DateTimeOffset> clock, bool native, VerifiedNativeBackend? backend = null)
    {
        if (grant is null || grant.Length != GrantBytes || license is null ||
            license.Length < 72 || license.Length > OfflineLicense.MaximumTicketBytes)
            throw new InvalidDataException("Invalid grant/license size.");
        if (programKey is null || programKey.Length != 32 || trustedPublicKey is null ||
            trustedPublicKey.Length != 65 || clock is null)
            throw new ArgumentException("Explicit key, trust anchor and clock required.");
        grant = (byte[])grant.Clone(); license = (byte[])license.Clone();
        trustedPublicKey = (byte[])trustedPublicKey.Clone();
        byte[] key = (byte[])programKey.Clone();
        try
        {
            byte[] payload = new byte[80], signature = new byte[64];
            Array.Copy(grant, payload, 80); Array.Copy(grant, 80, signature, 0, 64);
            if (!P256Signature.Verify(payload, signature, trustedPublicKey))
                throw new CryptographicException("Invalid program-key grant signature.");
            using var reader = new BinaryReader(new MemoryStream(payload, false));
            foreach (byte expected in Domain)
                if (reader.ReadByte() != expected) throw new InvalidDataException("Wrong grant domain.");
            byte[] licenseHash = reader.ReadBytes(32), keyHash = reader.ReadBytes(32);
            ulong keyFeatures = reader.ReadUInt64();
            using var sha = SHA256.Create();
            if (!CryptographicOperations.FixedTimeEquals(licenseHash, sha.ComputeHash(license)) ||
                !CryptographicOperations.FixedTimeEquals(keyHash, sha.ComputeHash(key)) ||
                !string.Equals(expectedKeyId, EncryptedIntegerMachine.IdentifyKey(key), StringComparison.Ordinal))
                throw new UnauthorizedAccessException("Grant license/key binding mismatch.");
            var claims = OfflineLicense.Verify(license, trustedPublicKey, expectedProduct, expectedDevice,
                requiredFeatures | keyFeatures, requestedSeats, clock());
            return EncryptedIntegerMachine.RegisterLicensedKey(key, claims.NotBefore, claims.Expires, clock, native, backend);
        }
        finally { Array.Clear(key, 0, key.Length); }
    }
}
