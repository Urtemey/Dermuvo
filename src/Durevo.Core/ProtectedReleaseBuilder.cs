using System.Security.Cryptography;
using System.Text.Json;
using Durevo.Runtime;

namespace Durevo.Core;

public sealed record ReleaseModulePlan(string Path, string InputSha256, string Mode, string[] Methods, Dictionary<string, string>? KeySlots = null);
public sealed record ProtectedReleasePlan(int Version, string Product, ulong Revision,
    string? RuntimeDirectory, string? NativePath, ReleaseModulePlan[] Modules, Dictionary<string, ulong>? KeyFeatures = null);
public sealed record ReleaseBuildAsset(string Path, byte[] Bytes);
public sealed record ProtectedReleaseResult(int Modules, int Files, string ManifestSha256);

// Trusted, quiescent build output only. This is not a hostile-filesystem sandbox or a runtime loader.
public static class ProtectedReleaseBuilder
{
    public const string ReportName = "durevo.build.json";
    public static readonly IReadOnlyList<string> RuntimeNames = Array.AsReadOnly(new[] {
        "Durevo.Runtime.dll", "BouncyCastle.Cryptography.dll", "BouncyCastle.LICENSE.md",
        "Mono.Cecil.dll", "Mono.Cecil.LICENSE.txt" });

    public static bool ContainsPath(string root, string candidate)
    {
        root = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(root));
        candidate = System.IO.Path.GetFullPath(candidate);
        return candidate.Equals(root, StringComparison.OrdinalIgnoreCase) ||
            candidate.StartsWith(root.EndsWith(System.IO.Path.DirectorySeparatorChar) ? root : root + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    public static ProtectedReleaseResult Build(string source, string destination, ProtectedReleasePlan plan,
        ECDsa signer, VmEncryptionKey? programKey = null, IReadOnlyList<ReleaseBuildAsset>? assets = null,
        IReadOnlyCollection<string>? forbiddenFileHashes = null, IReadOnlyDictionary<string, VmEncryptionKey>? keyring = null)
    {
        source = Path.GetFullPath(source); destination = Path.GetFullPath(destination);
        if (ContainsPath(source, destination) || ContainsPath(destination, source))
            throw new ArgumentException("Source and destination must be disjoint.");
        if (Directory.Exists(destination) || File.Exists(destination)) throw new IOException("Destination must be new.");
        CheckAncestors(Path.GetDirectoryName(destination)!);
        if (plan.Version != 1 || plan.Modules == null || plan.Modules.Length == 0 || plan.Modules.Length > 1000)
            throw new ArgumentException("Invalid release plan version or module selection.");
        // Snapshot caller-owned arrays before processing.
        var modules = plan.Modules.Select(m => m with { Methods = m.Methods?.ToArray() ?? throw new ArgumentException("Missing methods."), KeySlots = m.KeySlots == null ? null : new Dictionary<string, string>(m.KeySlots, StringComparer.Ordinal) }).ToArray();
        var payloads = (assets ?? []).Select(a => new ReleaseBuildAsset(a.Path, a.Bytes.ToArray())).ToArray();
        var inputs = ReleaseInventory.Capture(source);
        _ = SignedRelease.Encode(plan.Product, plan.Revision, inputs);
        var inputMap = inputs.ToDictionary(f => f.Path, StringComparer.Ordinal);
        var forbidden = new HashSet<string>(forbiddenFileHashes ?? [], StringComparer.OrdinalIgnoreCase);
        if (inputs.Any(f => forbidden.Contains(Convert.ToHexString(f.Sha256))) ||
            payloads.Any(a => forbidden.Contains(Convert.ToHexString(SHA256.HashData(a.Bytes)))))
            throw new ArgumentException("An active secret file was found in the release inputs.");
        if (inputs.Any(f => f.Path.Equals(ReportName, StringComparison.OrdinalIgnoreCase)))
            throw new IOException("Source already contains a Durevo build report.");
        bool vm = modules.Any(m => m.Mode != "obfuscate");
        bool native = modules.Any(m => m.Mode is "vm-encrypted-native" or "vm-encrypted-verified-native");
        var keys = keyring == null ? null : new Dictionary<string, VmEncryptionKey>(keyring, StringComparer.Ordinal);
        if (programKey != null && keys != null || vm != (programKey != null || keys != null))
            throw new ArgumentException("VM modules require either a shared key or an explicit keyring.");
        if (keys != null && (keys.Count == 0 || keys.Count > 10000 ||
            keys.Any(k => !ValidSlot(k.Key) || k.Value == null) ||
            keys.Values.Select(k => k.KeyId).Distinct(StringComparer.Ordinal).Count() != keys.Count))
            throw new ArgumentException("Key slots must be valid and use distinct key material.");
        var features = plan.KeyFeatures == null ? null : new Dictionary<string, ulong>(plan.KeyFeatures, StringComparer.Ordinal);
        if ((keys == null) != (features == null) || keys != null && !keys.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(features!.Keys))
            throw new ArgumentException("Keyring plans must explicitly define features for every key slot.");
        var usedSlots = new HashSet<string>(StringComparer.Ordinal);
        foreach (var module in modules)
        {
            if (keys == null || module.Mode == "obfuscate")
            {
                if (module.KeySlots != null) throw new ArgumentException("Key slot assignments require a keyring and a VM module.");
                continue;
            }
            if (module.KeySlots == null || module.KeySlots.Count != module.Methods.Length ||
                module.Methods.Any(m => !module.KeySlots.ContainsKey(m)))
                throw new ArgumentException("Every selected VM method must have exactly one key slot.");
            foreach (string slot in module.KeySlots.Values)
            {
                if (slot == null || !keys.ContainsKey(slot)) throw new ArgumentException("Unknown key slot.");
                usedSlots.Add(slot);
            }
        }
        if (keys != null && !usedSlots.SetEquals(keys.Keys)) throw new ArgumentException("Unused key slots are forbidden.");
        if (vm != (plan.RuntimeDirectory != null) || native != (plan.NativePath != null))
            throw new ArgumentException("Runtime/native destinations must match selected modes.");
        if (plan.RuntimeDirectory is { Length: > 0 }) ReleaseInventory.ValidatePath(plan.RuntimeDirectory);
        var expectedAssets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (vm) foreach (string name in RuntimeNames) expectedAssets.Add(Under(plan.RuntimeDirectory!, name));
        if (native)
        {
            ReleaseInventory.ValidatePath(plan.NativePath!);
            if (Path.GetFileName(plan.NativePath) is not ("durevo_vm.dll" or "libdurevo_vm.so"))
                throw new ArgumentException("Unsupported native library destination.");
            expectedAssets.Add(plan.NativePath!);
        }
        var assetPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var asset in payloads)
        {
            ReleaseInventory.ValidatePath(asset.Path);
            if (asset.Bytes.Length == 0 || !assetPaths.Add(asset.Path) || !expectedAssets.Contains(asset.Path))
                throw new ArgumentException("Unexpected, empty or duplicate runtime asset.");
            if (inputs.Any(f => f.Path.Equals(asset.Path, StringComparison.OrdinalIgnoreCase)))
                throw new IOException("Runtime asset would overwrite an existing release file: " + asset.Path);
        }
        if (!assetPaths.SetEquals(expectedAssets)) throw new ArgumentException("Required runtime assets missing.");
        NativeArtifactInfo? nativeInfo = native ? NativeArtifactInspector.Inspect(
            Path.GetFileName(plan.NativePath!), payloads.Single(a => a.Path.Equals(plan.NativePath, StringComparison.OrdinalIgnoreCase)).Bytes) : null;
        var selectedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var module in modules)
        {
            ReleaseInventory.ValidatePath(module.Path);
            if (!selectedPaths.Add(module.Path) || !inputMap.TryGetValue(module.Path, out var file))
                throw new ArgumentException("Duplicate or missing selected module: " + module.Path);
            if (module.Mode is not ("obfuscate" or "vm-encrypted" or "vm-encrypted-native" or "vm-encrypted-verified-native"))
                throw new ArgumentException("Unknown protection mode.");
            if (module.Mode != "obfuscate" &&
                (Parent(module.Path) != plan.RuntimeDirectory || RuntimeNames.Contains(Path.GetFileName(module.Path))))
                throw new ArgumentException("VM modules must share the declared managed runtime directory and cannot be runtime dependencies.");
            if (!string.Equals(module.InputSha256, Convert.ToHexString(file.Sha256), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Selected module hash differs from the plan: " + module.Path);
            var analysis = ProtectionAnalysis.Analyze(Resolve(source, module.Path));
            if (analysis.Sha256 != Convert.ToHexString(file.Sha256) || analysis.AssemblyBlockers.Length != 0)
                throw new InvalidDataException("Selected assembly changed or is unsupported.");
            if (module.Methods.Length == 0 || module.Methods.Distinct(StringComparer.Ordinal).Count() != module.Methods.Length)
                throw new ArgumentException("Select unique exact method signatures.");
            foreach (string signature in module.Methods)
            {
                var method = analysis.Methods.SingleOrDefault(m => m.Signature == signature);
                if (method == null || !method.ObfuscationEligible || (module.Mode != "obfuscate" && !method.IntegerVmEligible))
                    throw new NotSupportedException("Selected method cannot use the requested protection: " + signature);
            }
        }

        string parent = Path.GetDirectoryName(destination)!;
        Directory.CreateDirectory(parent);
        string staging = Path.Combine(parent, ".durevo-build-" + Guid.NewGuid().ToString("N"));
        if (Directory.Exists(staging) || File.Exists(staging)) throw new IOException("Staging collision.");
        Directory.CreateDirectory(staging);
        try
        {
            foreach (string directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
                Directory.CreateDirectory(Path.Combine(staging, Path.GetRelativePath(source, directory)));
            foreach (var file in inputs)
            {
                string from = Resolve(source, file.Path), to = Resolve(staging, file.Path);
                Directory.CreateDirectory(Path.GetDirectoryName(to)!);
                File.Copy(from, to, overwrite: false);
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(to, File.GetUnixFileMode(from));
            }
            AssertInventory(inputs, ReleaseInventory.Capture(staging));
            AssertInventory(inputs, ReleaseInventory.Capture(source));
            var reports = new List<object>();
            var removedSymbols = new List<string>();
            foreach (var module in modules)
            {
                string target = Resolve(staging, module.Path);
                string temporary = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
                var report = Protector.Protect(target, temporary, module.Methods,
                    virtualize: module.Mode != "obfuscate", native: module.Mode is "vm-encrypted-native" or "vm-encrypted-verified-native",
                    encryption: module.Mode == "obfuscate" ? null : programKey, verifiedNative: module.Mode == "vm-encrypted-verified-native",
                    methodKeys: module.KeySlots?.ToDictionary(p => p.Key, p => keys![p.Value], StringComparer.Ordinal));
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary, File.GetUnixFileMode(target));
                File.Move(temporary, target, overwrite: true);
                foreach (string candidate in new[] { Path.ChangeExtension(module.Path, ".pdb"), module.Path + ".mdb" })
                foreach (var symbol in inputs.Where(f => f.Path.Equals(candidate, StringComparison.OrdinalIgnoreCase)))
                {
                    File.Delete(Resolve(staging, symbol.Path));
                    removedSymbols.Add(symbol.Path);
                }
                reports.Add(new { module.Path, module.Mode, module.Methods, module.KeySlots, Protection = report });
            }
            foreach (var asset in payloads)
            {
                string target = Resolve(staging, asset.Path);
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                using var file = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                file.Write(asset.Bytes); file.Flush(true);
            }
            File.WriteAllText(Path.Combine(staging, ReportName), JsonSerializer.Serialize(new {
                Version = 1, plan.Product, plan.Revision,
                SourceInventorySha256 = Convert.ToHexString(SHA256.HashData(SignedRelease.Encode(plan.Product, plan.Revision, inputs))),
                ProgramKeyId = programKey?.KeyId, KeyFeatures = features, KeySlots = keys?.ToDictionary(p => p.Key, p => p.Value.KeyId, StringComparer.Ordinal), NativeArtifact = nativeInfo, Modules = reports, RemovedSymbols = removedSymbols,
                Assets = payloads.Select(a => new { a.Path, Sha256 = Convert.ToHexString(SHA256.HashData(a.Bytes)) }),
                Scope = "Transformed and signed immutable file tree. No runtime enforcement or update-feed compatibility acceptance."
            }, new JsonSerializerOptions { WriteIndented = true }));
            byte[] manifest = ReleaseSigner.Create(staging, plan.Product, plan.Revision, signer);
            using (var file = new FileStream(Path.Combine(staging, ReleaseInventory.ManifestName), FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { file.Write(manifest); file.Flush(true); }
            var verified = SignedRelease.Verify(staging, manifest, LicenseIssuer.ExportPublicKey(signer), plan.Product, plan.Revision);
            AssertInventory(inputs, ReleaseInventory.Capture(source));
            // Same-parent rename publishes only a completely transformed and verified tree.
            Directory.Move(staging, destination);
            return new ProtectedReleaseResult(modules.Length, verified.Files.Count, Convert.ToHexString(SHA256.HashData(manifest)));
        }
        finally
        {
            // Only remove the unique staging path created by this invocation, never a caller path.
            if (ContainsPath(parent, staging) && Path.GetFileName(staging).StartsWith(".durevo-build-", StringComparison.Ordinal)
                && Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
        }
    }

    private static bool ValidSlot(string value) => value.Length is > 0 and <= 64 &&
        value.All(c => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_');
    private static string Under(string directory, string name) => directory.Length == 0 ? name : directory + "/" + name;
    private static string Parent(string path) => path.Contains('/') ? path[..path.LastIndexOf('/')] : "";
    private static string Resolve(string root, string relative) => Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar));
    private static void CheckAncestors(string path)
    {
        for (var entry = new DirectoryInfo(path); entry != null; entry = entry.Parent)
        {
            if (File.Exists(entry.FullName)) throw new IOException("Output ancestor is a file.");
            if (entry.Exists && (entry.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Output ancestors cannot be symlinks/reparse points.");
        }
    }
    private static void AssertInventory(IReadOnlyList<ReleaseFile> expected, IReadOnlyList<ReleaseFile> actual)
    {
        if (expected.Count != actual.Count || expected.Where((f, i) => f.Path != actual[i].Path ||
            f.Length != actual[i].Length || !f.Sha256.SequenceEqual(actual[i].Sha256)).Any())
            throw new IOException("Release input/copy changed during staging.");
    }
}
