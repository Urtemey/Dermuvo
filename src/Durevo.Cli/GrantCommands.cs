using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Durevo.Core;

internal static class GrantCommands
{
    internal static void IssueRelease(string root, string slot, string licensePath, string programKeyPath,
        string issuerPath, string product, string floor, string output)
    {
        foreach (string path in new[] { licensePath, programKeyPath, issuerPath, output })
            if (ProtectedReleaseBuilder.ContainsPath(root, path))
                throw new ArgumentException("Issuance inputs and output must be outside the immutable release.");
        string password = Environment.GetEnvironmentVariable("DUREVO_KEY_PASSWORD")
            ?? throw new InvalidOperationException("DUREVO_KEY_PASSWORD is required.");
        if (password.Length < 16) throw new ArgumentException("Signing password must contain at least 16 characters.");
        byte[] key = ReleaseCommands.ReadBounded(programKeyPath, 32);
        try
        {
            using var issuer = ECDsa.Create();
            issuer.ImportFromEncryptedPem(Encoding.UTF8.GetString(ReleaseCommands.ReadBounded(issuerPath, 32768)), password);
            byte[] grant = ReleaseGrantIssuer.Issue(root, issuer,
                ReleaseCommands.ReadBounded(licensePath, Durevo.Runtime.OfflineLicense.MaximumTicketBytes),
                key, slot, product, ulong.Parse(floor, CultureInfo.InvariantCulture));
            output = Path.GetFullPath(output);
            Directory.CreateDirectory(Path.GetDirectoryName(output)!);
            using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            file.Write(grant); file.Flush(true);
            Console.WriteLine("Created grant using signed release feature policy (no program key included).");
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    internal static void Issue(string licensePath, string programKeyPath, string features, string issuerPath, string output)
    {
        string password = Environment.GetEnvironmentVariable("DUREVO_KEY_PASSWORD")
            ?? throw new InvalidOperationException("DUREVO_KEY_PASSWORD is required.");
        if (password.Length < 16) throw new ArgumentException("Signing password must contain at least 16 characters.");
        byte[] license = ReleaseCommands.ReadBounded(licensePath, Durevo.Runtime.OfflineLicense.MaximumTicketBytes);
        byte[] key = ReleaseCommands.ReadBounded(programKeyPath, 32);
        try
        {
            using var issuer = ECDsa.Create();
            issuer.ImportFromEncryptedPem(Encoding.UTF8.GetString(ReleaseCommands.ReadBounded(issuerPath,32768)),password);
            byte[] grant = ProgramKeyGrantIssuer.Issue(issuer,license,key,ulong.Parse(features,CultureInfo.InvariantCulture));
            output = Path.GetFullPath(output);
            Directory.CreateDirectory(Path.GetDirectoryName(output)!);
            using var file = new FileStream(output,FileMode.CreateNew,FileAccess.Write,FileShare.None);
            file.Write(grant); file.Flush(true);
            Console.WriteLine("Created signed program-key grant (no program key included).");
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
