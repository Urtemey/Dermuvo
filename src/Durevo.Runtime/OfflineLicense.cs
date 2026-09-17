using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Durevo.Runtime;

public sealed class LicenseClaims
{
    public string Id { get; }
    public string Product { get; }
    public string Device { get; }
    public long NotBefore { get; }
    public long Expires { get; }
    public ulong Features { get; }
    public uint Seats { get; }

    public LicenseClaims(string id, string product, string device, long notBefore, long expires, ulong features, uint seats)
    {
        Id = id; Product = product; Device = device; NotBefore = notBefore;
        Expires = expires; Features = features; Seats = seats;
        Validate();
    }
    internal void Validate()
    {
        foreach (var s in new[] { Id, Product, Device })
            if (string.IsNullOrWhiteSpace(s) || new UTF8Encoding(false, true).GetByteCount(s) > 256)
                throw new ArgumentException("License identifiers must contain 1..256 UTF-8 bytes.");
        if (NotBefore < 0 || Expires <= NotBefore || Expires > 253402300799L || Seats == 0)
            throw new ArgumentException("Invalid license validity interval or seat count.");
    }
}

// Fixed format: signed payload followed by a 64-byte IEEE P1363 ECDSA signature.
// Trust anchors are supplied by the host, never taken from the untrusted ticket.
public static class OfflineLicense
{
    private static readonly byte[] Domain = Encoding.ASCII.GetBytes("DUR-LIC1");
    private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    public const int MaximumTicketBytes = 4096;

    public static byte[] EncodeClaims(LicenseClaims claims)
    {
        if (claims is null) throw new ArgumentNullException(nameof(claims));
        claims.Validate();
        using var memory = new MemoryStream();
        using var writer = new BinaryWriter(memory, Utf8, true);
        writer.Write(Domain);
        WriteText(writer, claims.Id); WriteText(writer, claims.Product); WriteText(writer, claims.Device);
        writer.Write(claims.NotBefore); writer.Write(claims.Expires);
        writer.Write(claims.Features); writer.Write(claims.Seats);
        writer.Flush();
        return memory.ToArray();
    }

    // Authenticates and parses only. It does not authorize execution or check current validity.
    // Issuers may inspect future-dated tickets; clients must use Verify with explicit policy.
    public static LicenseClaims VerifySignature(byte[] ticket, byte[] trustedPublicKey)
    {
        if (ticket is null || ticket.Length < Domain.Length + 64 || ticket.Length > MaximumTicketBytes)
            throw new InvalidDataException("Invalid license size.");
        if (trustedPublicKey is null || trustedPublicKey.Length != 65 || trustedPublicKey[0] != 4)
            throw new ArgumentException("Expected an uncompressed P-256 public key.");

        // Snapshot caller-owned buffers before cryptographic verification and parsing.
        ticket = (byte[])ticket.Clone();
        trustedPublicKey = (byte[])trustedPublicKey.Clone();
        int length = ticket.Length - 64;
        var payload = new byte[length]; var signature = new byte[64];
        Array.Copy(ticket, payload, length); Array.Copy(ticket, length, signature, 0, 64);
        if (!P256Signature.Verify(payload, signature, trustedPublicKey))
            throw new CryptographicException("Invalid license signature.");
        using var memory = new MemoryStream(payload, false);
        using var reader = new BinaryReader(memory, Utf8, true);
        foreach (byte expected in Domain)
            if (reader.ReadByte() != expected) throw new InvalidDataException("Wrong license domain/version.");
        var claims = new LicenseClaims(ReadText(reader), ReadText(reader), ReadText(reader),
            reader.ReadInt64(), reader.ReadInt64(), reader.ReadUInt64(), reader.ReadUInt32());
        if (memory.Position != memory.Length) throw new InvalidDataException("Trailing license data.");
        return claims;
    }

    public static LicenseClaims Verify(byte[] ticket, byte[] trustedPublicKey,
        string expectedProduct, string expectedDevice, ulong requiredFeatures, uint requestedSeats, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(expectedProduct) || string.IsNullOrWhiteSpace(expectedDevice) || requestedSeats == 0)
            throw new ArgumentException("Explicit product, device and requested seats are required.");
        var claims = VerifySignature(ticket, trustedPublicKey);
        if (!string.Equals(claims.Product, expectedProduct, StringComparison.Ordinal) ||
            !string.Equals(claims.Device, expectedDevice, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("License product/device mismatch.");
        long time = now.ToUnixTimeSeconds();
        if (time < claims.NotBefore || time >= claims.Expires)
            throw new UnauthorizedAccessException("License is not currently valid.");
        if ((claims.Features & requiredFeatures) != requiredFeatures || requestedSeats > claims.Seats)
            throw new UnauthorizedAccessException("License entitlement exceeded.");
        return claims;
    }

    private static void WriteText(BinaryWriter writer, string text)
    {
        byte[] bytes = Utf8.GetBytes(text); writer.Write(checked((ushort)bytes.Length)); writer.Write(bytes);
    }
    private static string ReadText(BinaryReader reader)
    {
        int count = reader.ReadUInt16();
        if (count == 0 || count > 256) throw new InvalidDataException("Invalid identifier length.");
        var bytes = reader.ReadBytes(count);
        if (bytes.Length != count) throw new EndOfStreamException();
        return Utf8.GetString(bytes);
    }
}
