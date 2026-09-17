using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Durevo.Runtime;

public sealed class ReleaseFile
{
    public string Path { get; }
    public long Length { get; }
    private readonly byte[] hash;
    public byte[] Sha256 => (byte[])hash.Clone();
    public ReleaseFile(string path, long length, byte[] sha256)
    {
        ReleaseInventory.ValidatePath(path);
        if (length < 0 || sha256 is null || sha256.Length != 32) throw new ArgumentException("Invalid file entry.");
        Path = path; Length = length; hash = (byte[])sha256.Clone();
    }
}

public sealed class VerifiedRelease
{
    public string Product { get; }
    public ulong Revision { get; }
    public IReadOnlyList<ReleaseFile> Files { get; }
    internal VerifiedRelease(string product, ulong revision, List<ReleaseFile> files)
    { Product = product; Revision = revision; Files = files.AsReadOnly(); }
}

// Point-in-time filesystem inventory. This is not a race-free executable loader.
public static class ReleaseInventory
{
    public const string ManifestName = "durevo.release";
    public const int MaximumFiles = 10000;
    internal static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);

    public static void ValidatePath(string path)
    {
        if (string.IsNullOrEmpty(path) || Utf8.GetByteCount(path) > 1024 ||
            path.Any(c => c < 32 || c == 127 || "\\:\"<>|?*".IndexOf(c) >= 0))
            throw new InvalidDataException("Invalid portable release path.");
        foreach (string part in path.Split('/'))
        {
            if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(" ", StringComparison.Ordinal) ||
                part.EndsWith(".", StringComparison.Ordinal)) throw new InvalidDataException("Ambiguous release path.");
            string stem = part.Split('.')[0].ToUpperInvariant();
            if (stem is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
                ((stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) &&
                 stem.Length == 4 && "123456789¹²³".IndexOf(stem[3]) >= 0))
                throw new InvalidDataException("Reserved device path.");
        }
        if (string.Equals(path, ManifestName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Manifest cannot list itself.");
    }

    public static IReadOnlyList<ReleaseFile> Capture(string root, bool permitManifest = false)
    {
        root = System.IO.Path.GetFullPath(root);
        for (var parent = new DirectoryInfo(root); parent != null; parent = parent.Parent)
            RejectLink(parent.FullName);
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException(root);
        var files = new List<ReleaseFile>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<(string Absolute, string Relative, int Depth)>();
        pending.Push((root, "", 0));
        int nodes = 0;
        while (pending.Count > 0)
        {
            var dir = pending.Pop();
            if (dir.Depth > 128) throw new InvalidDataException("Release directory nesting too deep.");
            foreach (var entry in Directory.EnumerateFileSystemEntries(dir.Absolute))
            {
                if (++nodes > MaximumFiles * 2) throw new InvalidDataException("Too many filesystem entries.");
                RejectLink(entry);
                string name = System.IO.Path.GetFileName(entry);
                string relative = dir.Relative.Length == 0 ? name : dir.Relative + "/" + name;
                var attributes = File.GetAttributes(entry);
                if (dir.Relative.Length == 0 && name == ManifestName && permitManifest &&
                    (attributes & FileAttributes.Directory) == 0) continue;
                ValidatePath(relative);
                if (!names.Add(relative)) throw new InvalidDataException("Case-insensitive path collision.");
                if ((attributes & FileAttributes.Directory) != 0)
                { pending.Push((entry, relative, dir.Depth + 1)); continue; }
                if (files.Count == MaximumFiles) throw new InvalidDataException("Too many release files.");
                using var stream = new FileStream(entry, FileMode.Open, FileAccess.Read, FileShare.Read);
                long size = stream.Length;
                using var sha = SHA256.Create();
                var digest = sha.ComputeHash(stream);
                if (stream.Length != size) throw new IOException("File changed during inventory.");
                files.Add(new ReleaseFile(relative, size, digest));
            }
        }
        return files.OrderBy(f => f.Path, StringComparer.Ordinal).ToArray();
    }
    private static void RejectLink(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Symlinks/reparse points are not supported in release roots.");
    }
}

public static class SignedRelease
{
    private static readonly byte[] Domain = Encoding.ASCII.GetBytes("DUR-REL1");
    public const int MaximumManifestBytes = 16 * 1024 * 1024;

    public static byte[] Encode(string product, ulong revision, IReadOnlyList<ReleaseFile> files)
    {
        ValidateProduct(product);
        if (revision == 0 || files.Count == 0 || files.Count > ReleaseInventory.MaximumFiles)
            throw new ArgumentException("Invalid release revision or file count.");
        using var memory = new MemoryStream();
        using var writer = new BinaryWriter(memory, ReleaseInventory.Utf8, true);
        writer.Write(Domain); WriteText(writer, product); writer.Write(revision); writer.Write((uint)files.Count);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? previous = null;
        foreach (var file in files.OrderBy(f => f.Path, StringComparer.Ordinal))
        {
            ReleaseInventory.ValidatePath(file.Path);
            if (!names.Add(file.Path) || (previous != null && StringComparer.Ordinal.Compare(previous, file.Path) >= 0))
                throw new ArgumentException("Duplicate release path.");
            previous = file.Path;
            WriteText(writer, file.Path); writer.Write(file.Length); writer.Write(file.Sha256);
        }
        writer.Flush();
        if (memory.Length + 64 > MaximumManifestBytes) throw new InvalidDataException("Manifest too large.");
        return memory.ToArray();
    }

    public static VerifiedRelease Verify(string root, byte[] signedManifest, byte[] pinnedPublicKey,
        string expectedProduct, ulong minimumRevision)
    {
        ValidateProduct(expectedProduct);
        if (minimumRevision == 0) throw new ArgumentException("Explicit positive revision floor required.");
        if (signedManifest is null || signedManifest.Length < 64 + 8 || signedManifest.Length > MaximumManifestBytes)
            throw new InvalidDataException("Invalid signed manifest size.");
        if (pinnedPublicKey is null || pinnedPublicKey.Length != 65 || pinnedPublicKey[0] != 4)
            throw new ArgumentException("Expected pinned P-256 public point.");
        signedManifest = (byte[])signedManifest.Clone(); pinnedPublicKey = (byte[])pinnedPublicKey.Clone();
        int length = signedManifest.Length - 64;
        byte[] payload = new byte[length], signature = new byte[64];
        Array.Copy(signedManifest, payload, length); Array.Copy(signedManifest, length, signature, 0, 64);
        if (!P256Signature.Verify(payload, signature, pinnedPublicKey))
                throw new CryptographicException("Invalid release signature.");

        using var memory = new MemoryStream(payload, false);
        using var reader = new BinaryReader(memory, ReleaseInventory.Utf8, true);
        foreach (var b in Domain) if (reader.ReadByte() != b) throw new InvalidDataException("Wrong release domain/version.");
        string product = ReadText(reader, 256);
        ValidateProduct(product);
        ulong revision = reader.ReadUInt64();
        if (!string.Equals(expectedProduct, product, StringComparison.Ordinal) || revision < minimumRevision)
            throw new UnauthorizedAccessException("Release product/revision rejected.");
        uint count = reader.ReadUInt32();
        if (count == 0 || count > ReleaseInventory.MaximumFiles) throw new InvalidDataException("Invalid file count.");
        var files = new List<ReleaseFile>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? previous = null;
        for (uint i = 0; i < count; i++)
        {
            string path = ReadText(reader, 1024);
            ReleaseInventory.ValidatePath(path);
            if (!names.Add(path) || (previous != null && StringComparer.Ordinal.Compare(previous, path) >= 0))
                throw new InvalidDataException("Duplicate or unsorted path.");
            previous = path;
            long size = reader.ReadInt64();
            byte[] digest = reader.ReadBytes(32);
            files.Add(new ReleaseFile(path, size, digest));
        }
        if (memory.Position != memory.Length) throw new InvalidDataException("Trailing manifest data.");
        var actual = ReleaseInventory.Capture(root, permitManifest: true);
        if (actual.Count != files.Count) throw new InvalidDataException("Missing or unexpected release files.");
        for (int i = 0; i < files.Count; i++)
            if (!string.Equals(actual[i].Path, files[i].Path, StringComparison.Ordinal) || actual[i].Length != files[i].Length ||
                !CryptographicOperations.FixedTimeEquals(actual[i].Sha256, files[i].Sha256))
                throw new InvalidDataException("Release file differs: " + files[i].Path);
        return new VerifiedRelease(product, revision, files);
    }
    private static void ValidateProduct(string product)
    {
        if (string.IsNullOrWhiteSpace(product) || ReleaseInventory.Utf8.GetByteCount(product) > 256)
            throw new ArgumentException("Invalid release product.");
    }
    private static void WriteText(BinaryWriter writer, string value)
    { var bytes = ReleaseInventory.Utf8.GetBytes(value); writer.Write(checked((ushort)bytes.Length)); writer.Write(bytes); }
    private static string ReadText(BinaryReader reader, int maximum)
    {
        int length = reader.ReadUInt16();
        if (length == 0 || length > maximum) throw new InvalidDataException("Invalid text length.");
        var bytes = reader.ReadBytes(length);
        if (bytes.Length != length) throw new EndOfStreamException();
        return ReleaseInventory.Utf8.GetString(bytes);
    }
}
