using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
namespace Durevo.Runtime;

public sealed class VerifiedNativeImage
{
    private readonly byte[] bytes;
    public string Product { get; }
    public ulong Revision { get; }
    private VerifiedNativeImage(byte[] image, VerifiedRelease release) { bytes = image; Product = release.Product; Revision = release.Revision; }
    public VerifiedNativeBackend Load() => VerifiedNativeBackend.LoadSnapshot(bytes, Product, Revision);
    public static VerifiedNativeImage Capture(VerifiedRelease release, string root, string relativePath)
    {
        if (release is null) throw new ArgumentNullException(nameof(release));
        ReleaseInventory.ValidatePath(relativePath);
        var entry = release.Files.SingleOrDefault(f => f.Path == relativePath)
            ?? throw new UnauthorizedAccessException("Native image is not in the verified release.");
        if (entry.Length < 64 || entry.Length > 64 * 1024 * 1024) throw new InvalidDataException("Invalid native image size.");
        string path = Path.GetFullPath(Path.Combine(Path.GetFullPath(root), relativePath.Replace('/', Path.DirectorySeparatorChar)));
        for (var parent = new DirectoryInfo(Path.GetDirectoryName(path)!); parent != null; parent = parent.Parent)
            if ((parent.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Native image ancestors cannot be symlinks.");
        if ((File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw new IOException("Expected a regular native image.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length != entry.Length) throw new InvalidDataException("Native image length changed.");
        var bytes = new byte[(int)entry.Length];
        int offset = 0;
        while (offset < bytes.Length) {
            int read = stream.Read(bytes, offset, bytes.Length - offset);
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
        if (stream.ReadByte() != -1) throw new IOException("Native image grew during capture.");
        using var sha = SHA256.Create();
        if (!CryptographicOperations.FixedTimeEquals(sha.ComputeHash(bytes), entry.Sha256))
            throw new CryptographicException("Native image differs from signed bytes.");
        return new VerifiedNativeImage(bytes, release);
    }
}
