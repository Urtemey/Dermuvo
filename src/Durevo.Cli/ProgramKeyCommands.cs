using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Runtime;

internal static class ProgramKeyCommands
{
    internal static void Create(string path)
    {
        path = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using var stream = new FileStream(path, options);
            stream.Write(key); stream.Flush(true);
            Console.WriteLine("Created separate program key; key ID: " + EncryptedIntegerMachine.IdentifyKey(key));
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    internal static VmEncryptionKey Read(string path)
    {
        byte[] key = ReleaseCommands.ReadBounded(path, 32);
        try { return new VmEncryptionKey(key); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
