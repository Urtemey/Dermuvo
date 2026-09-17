using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Durevo.Core;
using Durevo.Runtime;

internal static class ProtectedReleaseCommands
{
    internal static void Build(string[] args)
    {
        string source = Path.GetFullPath(args[1]), output = Path.GetFullPath(args[2]);
        void CheckControl(string path)
        {
            if (ProtectedReleaseBuilder.ContainsPath(source, path) || ProtectedReleaseBuilder.ContainsPath(output, path))
                throw new ArgumentException("Plan, signing key, program keys, keyring and native input must be outside source/output roots.");
        }
        foreach (string control in args.Skip(3)) CheckControl(control);
        var plan = JsonSerializer.Deserialize<ProtectedReleasePlan>(ReleaseCommands.ReadBounded(args[3], 1024 * 1024),
            new JsonSerializerOptions { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow })
            ?? throw new ArgumentException("Missing release plan.");
        string password = Environment.GetEnvironmentVariable("DUREVO_KEY_PASSWORD")
            ?? throw new InvalidOperationException("DUREVO_KEY_PASSWORD is required.");
        if (password.Length < 16) throw new ArgumentException("Signing password must contain at least 16 characters.");
        byte[] pem = ReleaseCommands.ReadBounded(args[4], 32768);
        var forbidden = new List<string> { Convert.ToHexString(SHA256.HashData(pem)) };
        using var signer = ECDsa.Create();
        signer.ImportFromEncryptedPem(Encoding.UTF8.GetString(pem), password);
        VmEncryptionKey? key = null;
        Dictionary<string, VmEncryptionKey>? keys = null;
        VmEncryptionKey ReadKey(string path)
        {
            CheckControl(path);
            byte[] raw = ReleaseCommands.ReadBounded(path, 32);
            try
            {
                forbidden.Add(Convert.ToHexString(SHA256.HashData(raw)));
                return new VmEncryptionKey(raw);
            }
            finally { CryptographicOperations.ZeroMemory(raw); }
        }
        try
        {
            if (args[0] == "protect-release-keyring")
            {
                keys = new Dictionary<string, VmEncryptionKey>(StringComparer.Ordinal);
                byte[] map = ReleaseCommands.ReadBounded(args[5], 1024 * 1024);
                forbidden.Add(Convert.ToHexString(SHA256.HashData(map)));
                using var document = JsonDocument.Parse(map);
                if (document.RootElement.ValueKind != JsonValueKind.Object) throw new ArgumentException("Keyring must be a slot-to-key-file object.");
                string directory = Path.GetDirectoryName(Path.GetFullPath(args[5]))!;
                foreach (var entry in document.RootElement.EnumerateObject())
                {
                    if (keys.Count >= 10000 || keys.ContainsKey(entry.Name) || entry.Value.ValueKind != JsonValueKind.String ||
                        string.IsNullOrWhiteSpace(entry.Value.GetString()))
                        throw new ArgumentException("Invalid or duplicate keyring entry.");
                    string path = Path.GetFullPath(entry.Value.GetString()!, directory);
                    keys.Add(entry.Name, ReadKey(path));
                }
            }
            else if (args.Length >= 6) key = ReadKey(args[5]);
            var assets = new List<ReleaseBuildAsset>();
            if (plan.RuntimeDirectory != null)
            {
                foreach (string name in ProtectedReleaseBuilder.RuntimeNames)
                {
                    string path = name == "Durevo.Runtime.dll" ? typeof(IntegerMachine).Assembly.Location :
                        Path.Combine(AppContext.BaseDirectory, "runtime-dependencies", name);
                    string relative = plan.RuntimeDirectory.Length == 0 ? name : plan.RuntimeDirectory + "/" + name;
                    assets.Add(new(relative, File.ReadAllBytes(path)));
                }
            }
            if (args.Length == 7)
            {
                if (plan.NativePath == null || Path.GetFileName(args[6]) != Path.GetFileName(plan.NativePath))
                    throw new ArgumentException("Native input name must match the declared destination.");
                assets.Add(new(plan.NativePath, ReleaseCommands.ReadBounded(args[6], 64 * 1024 * 1024)));
            }
            var result = ProtectedReleaseBuilder.Build(source, output, plan, signer, key, assets, forbidden, keys);
            Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        }
        finally
        {
            key?.Dispose();
            if (keys != null) foreach (var authority in keys.Values) authority.Dispose();
        }
    }
}
