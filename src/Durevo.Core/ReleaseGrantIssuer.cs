using System.Security.Cryptography;
using System.Text.Json;
using Durevo.Runtime;

namespace Durevo.Core;

// Issuer-side only. Policy is read from the exact bytes authenticated by the release.
public static class ReleaseGrantIssuer
{
    public static byte[] Issue(string root, ECDsa issuer, byte[] license, byte[] programKey,
        string slot, string expectedProduct, ulong minimumRevision)
    {
        root = Path.GetFullPath(root);
        byte[] publicKey = LicenseIssuer.ExportPublicKey(issuer);
        var release = SignedRelease.Verify(root, Read(Path.Combine(root, ReleaseInventory.ManifestName),
            SignedRelease.MaximumManifestBytes), publicKey, expectedProduct, minimumRevision);
        var entry = release.Files.SingleOrDefault(f => f.Path == ProtectedReleaseBuilder.ReportName)
            ?? throw new InvalidDataException("Signed build policy is missing.");
        byte[] report = Read(Path.Combine(root, ProtectedReleaseBuilder.ReportName), 16 * 1024 * 1024);
        if (report.LongLength != entry.Length || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(report), entry.Sha256))
            throw new CryptographicException("Build policy differs from the verified release.");
        using var document = JsonDocument.Parse(report);
        var policy = document.RootElement;
        UniqueProperties(policy);
        if (policy.GetProperty("Version").GetInt32() != 1 ||
            policy.GetProperty("Product").GetString() != release.Product ||
            policy.GetProperty("Revision").GetUInt64() != release.Revision)
            throw new InvalidDataException("Build policy identity mismatch.");
        var identities = policy.GetProperty("KeySlots");
        var features = policy.GetProperty("KeyFeatures");
        if (identities.ValueKind != JsonValueKind.Object || features.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Release does not define keyring feature policy.");
        UniqueProperties(identities); UniqueProperties(features);
        if (!identities.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal)
            .SetEquals(features.EnumerateObject().Select(p => p.Name)))
            throw new InvalidDataException("Incomplete release key feature policy.");
        if (!identities.TryGetProperty(slot, out var expectedId) || !features.TryGetProperty(slot, out var required))
            throw new UnauthorizedAccessException("Unknown release key slot.");
        if (programKey is null || programKey.Length != 32) throw new ArgumentException("Expected 32-byte program key.");
        byte[] key = (byte[])programKey.Clone();
        try
        {
            if (expectedId.GetString() != EncryptedIntegerMachine.IdentifyKey(key))
                throw new UnauthorizedAccessException("Program key does not match the signed slot.");
            if (license is null || license.Length > OfflineLicense.MaximumTicketBytes)
                throw new ArgumentException("Invalid license.");
            byte[] ticket = (byte[])license.Clone();
            var claims = OfflineLicense.VerifySignature(ticket, publicKey);
            if (claims.Product != release.Product) throw new UnauthorizedAccessException("License product differs from release.");
            return ProgramKeyGrantIssuer.Issue(issuer, ticket, key, required.GetUInt64());
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static void UniqueProperties(JsonElement value)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
            if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate policy property.");
    }

    private static byte[] Read(string path, int maximum)
    {
        for (var directory = new DirectoryInfo(Path.GetDirectoryName(path)!); directory != null; directory = directory.Parent)
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Policy ancestors cannot be links.");
        if ((File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw new IOException("Expected regular policy file.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length <= 0 || stream.Length > maximum) throw new InvalidDataException("Policy file size out of bounds.");
        byte[] bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new IOException("Policy file grew during capture.");
        return bytes;
    }
}
