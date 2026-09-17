using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;

namespace Durevo.Runtime;

/// <summary>A private, hash-verified byte snapshot of one managed assembly.</summary>
public sealed class VerifiedManagedImage
{
    private readonly byte[] image;
    public string RelativePath { get; }
    public string Product { get; }
    public ulong Revision { get; }
    private VerifiedManagedImage(byte[] bytes, string path, VerifiedRelease release)
    { image = bytes; RelativePath = path; Product = release.Product; Revision = release.Revision; }

    // Dependencies follow host assembly resolution. This authenticates the entry image,
    // not the dependency closure or native libraries. Do not represent it as a full loader.
    public Assembly Load() => Assembly.Load(image);
    internal Stream OpenMetadata() => new MemoryStream(image, writable: false);

    public static VerifiedManagedImage Capture(VerifiedRelease release, string root, string relativePath,
        int maximumBytes = 64 * 1024 * 1024)
    {
        if (release is null) throw new ArgumentNullException(nameof(release));
        if (maximumBytes < 1 || maximumBytes > 64 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        ReleaseInventory.ValidatePath(relativePath);
        if (!relativePath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("A managed DLL is required.");
        var entry = release.Files.SingleOrDefault(f => string.Equals(f.Path, relativePath, StringComparison.Ordinal))
            ?? throw new UnauthorizedAccessException("Image is not in the verified release.");
        if (entry.Length == 0 || entry.Length > maximumBytes)
            throw new InvalidDataException("Managed image exceeds the configured size limit.");
        string path = Path.GetFullPath(Path.Combine(Path.GetFullPath(root),
            relativePath.Replace('/', Path.DirectorySeparatorChar)));
        for (var parent = new DirectoryInfo(Path.GetDirectoryName(path)!); parent != null; parent = parent.Parent)
            if ((parent.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Managed image ancestors cannot be symlinks.");
        if ((File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw new IOException("Expected a regular managed image path.");
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length != entry.Length) throw new InvalidDataException("Image length changed.");
        var bytes = new byte[(int)entry.Length];
        int offset = 0;
        while (offset < bytes.Length)
        {
            int read = file.Read(bytes, offset, bytes.Length - offset);
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
        if (file.ReadByte() != -1) throw new IOException("Image grew during capture.");
        using var sha = SHA256.Create();
        if (!CryptographicOperations.FixedTimeEquals(sha.ComputeHash(bytes), entry.Sha256))
            throw new CryptographicException("Captured image differs from the signed release.");
        // Only this validated buffer is used by Load; the path is never reopened there.
        return new VerifiedManagedImage(bytes, relativePath, release);
    }
}
