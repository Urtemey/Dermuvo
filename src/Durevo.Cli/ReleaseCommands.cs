using System.Globalization;
using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Runtime;

internal static class ReleaseCommands
{
    internal static void Verify(string root, string publicKeyPath, string product, string floor)
    {
        string signaturePath = Path.Combine(root, ReleaseInventory.ManifestName);
        var result = SignedRelease.Verify(root, ReadBounded(signaturePath, SignedRelease.MaximumManifestBytes),
            ReadBounded(publicKeyPath, 65), product, ulong.Parse(floor, CultureInfo.InvariantCulture));
        Console.WriteLine($"Verified {result.Product} revision {result.Revision}: {result.Files.Count} files.");
    }

    internal static void Sign(string root, string product, string revision, string encryptedKeyPath)
    {
        root = Path.GetFullPath(root);
        encryptedKeyPath = Path.GetFullPath(encryptedKeyPath);
        var relative = Path.GetRelativePath(root, encryptedKeyPath);
        if (!Path.IsPathRooted(relative) && relative != ".." &&
            !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new ArgumentException("Issuer key must be outside the release directory.");
        string password = Environment.GetEnvironmentVariable("DUREVO_KEY_PASSWORD")
            ?? throw new InvalidOperationException("DUREVO_KEY_PASSWORD is required; passwords are not accepted on the command line.");
        if (password.Length < 16) throw new ArgumentException("Signing password must contain at least 16 characters.");
        byte[] encrypted = ReadBounded(encryptedKeyPath, 32768);
        using var signer = ECDsa.Create();
        signer.ImportFromEncryptedPem(System.Text.Encoding.UTF8.GetString(encrypted), password);
        byte[] signed = ReleaseSigner.Create(root, product, ulong.Parse(revision, CultureInfo.InvariantCulture), signer);
        string destination = Path.Combine(root, ReleaseInventory.ManifestName);
        string staging = Path.Combine(root, ".signature-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var file = new FileStream(staging, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { file.Write(signed); file.Flush(flushToDisk: true); }
            File.Move(staging, destination, overwrite: false);
        }
        finally { if (File.Exists(staging)) File.Delete(staging); }
        Console.WriteLine("Signed release manifest written.");
    }

    internal static byte[] ReadBounded(string path, int maximum)
    {
        for (var parent = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(path))!); parent != null; parent = parent.Parent)
            if ((parent.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Key/manifest ancestors cannot be symlinks.");
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Key/manifest symlinks are not accepted.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        long length = stream.Length;
        if (length == 0 || length > maximum) throw new InvalidDataException("Input file size out of bounds.");
        byte[] result = new byte[(int)length];
        stream.ReadExactly(result);
        if (stream.ReadByte() != -1) throw new IOException("Input changed during reading.");
        return result;
    }
}
