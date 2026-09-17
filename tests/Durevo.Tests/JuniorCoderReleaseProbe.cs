using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using Durevo.Core;
using Durevo.Runtime;

internal static class JuniorCoderReleaseProbe
{
    internal static void Run(string snapshots, string evidence, string cli, string nativeLibrary)
    {
        snapshots = Path.GetFullPath(snapshots); evidence = Path.GetFullPath(evidence);
        cli = Path.GetFullPath(cli); nativeLibrary = Path.GetFullPath(nativeLibrary);
        if (Directory.Exists(evidence) || File.Exists(evidence)) throw new IOException("Evidence directory must be new.");
        Directory.CreateDirectory(evidence);
        string source = Path.Combine(evidence, "input");
        Directory.CreateDirectory(Path.Combine(source, "Managed"));
        string[] names = ["JuniorCoder.LicenseKey.dll", "CodeAnalyzer.dll", "JuniorCoder.GameScene.dll"];
        var modules = new List<ReleaseModulePlan>();
        const string parserType = "JuniorCoder.Scripts.Game.LogicLua.PythonCodeHandlerBeforeLaunch";
        foreach (string name in names)
        {
            string input = Path.Combine(snapshots, name);
            var analysis = ProtectionAnalysis.Analyze(input);
            File.Copy(input, Path.Combine(source, "Managed", name));
            string[] methods = name switch {
                "JuniorCoder.LicenseKey.dll" => analysis.Methods.Where(m => m.Signature.Contains(" StringCipher::") && m.ObfuscationEligible).Select(m => m.Signature).ToArray(),
                "CodeAnalyzer.dll" => analysis.Methods.Where(m => m.Signature.Contains("JuniorCoder.Scripts.CodeAnalyzer.") && m.ObfuscationEligible).Select(m => m.Signature).ToArray(),
                _ => analysis.Methods.Where(m => m.Signature == "System.Boolean " + parserType + "::HasMultipleTopLevelArguments(System.String)").Select(m => m.Signature).ToArray()
            };
            if (methods.Length != (name == "JuniorCoder.LicenseKey.dll" ? 4 : name == "CodeAnalyzer.dll" ? 10 : 1))
                throw new InvalidDataException("Actual snapshot selection changed; review the probe.");
            modules.Add(new("Managed/" + name, analysis.Sha256, name == "JuniorCoder.GameScene.dll" ? "vm-encrypted-verified-native" : "obfuscate", methods));
        }
        string nativeName = Path.GetFileName(nativeLibrary);
        var plan = new ProtectedReleasePlan(1, "JuniorCoder-Protection-Pilot", 1, "Managed", "Plugins/x86_64/" + nativeName, modules.ToArray());
        var assets = ProtectedReleaseBuilder.RuntimeNames.Select(name => new ReleaseBuildAsset("Managed/" + name,
            File.ReadAllBytes(name == "Durevo.Runtime.dll" ? typeof(IntegerMachine).Assembly.Location :
                Path.Combine(Path.GetDirectoryName(cli)!, "runtime-dependencies", name)))).ToList();
        assets.Add(new(plan.NativePath!, File.ReadAllBytes(nativeLibrary)));
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        using var programKey = new VmEncryptionKey(key);
        string package = Path.Combine(evidence, "package");
        var original = new AssemblyLoadContext("product-package-original", true);
        var load = new ProtectedReleaseCliSuite.PackageContext(Path.Combine(package, "Managed"),
            Path.Combine(package, plan.NativePath!.Replace('/', Path.DirectorySeparatorChar)), requireVerified: true);
        int checks = 0;
        void Check(bool condition, string message) { checks++; if (!condition) throw new Exception(message); }
        try
        {
            var built = ProtectedReleaseBuilder.Build(source, package, plan, signer, programKey, assets);
            byte[] publicKey = LicenseIssuer.ExportPublicKey(signer);
            File.WriteAllBytes(Path.Combine(evidence, "publisher.bin"), publicKey);
            var verified = SignedRelease.Verify(package, File.ReadAllBytes(Path.Combine(package, ReleaseInventory.ManifestName)), publicKey, plan.Product, 1);
            Check(verified.Files.Count == built.Files && built.Modules == 3, "Signed package mismatch.");
            var parser = load.LoadFromAssemblyPath(Path.Combine(package, "Managed", "JuniorCoder.GameScene.dll"))
                .GetType(parserType, true)!.GetMethod("HasMultipleTopLevelArguments", BindingFlags.Static | BindingFlags.NonPublic)!;
            var baselineParser = original.LoadFromAssemblyPath(Path.Combine(source, "Managed", "JuniorCoder.GameScene.dll"))
                .GetType(parserType, true)!.GetMethod(parser.Name, BindingFlags.Static | BindingFlags.NonPublic)!;
            object? Observe(MethodInfo method, string? value) {
                try { return method.Invoke(null, [value]); }
                catch (TargetInvocationException e) { return e.InnerException!.GetType().FullName; }
            }
            Check(Equals(Observe(parser, "say(a,b)"), typeof(UnauthorizedAccessException).FullName), "Parser ran before key registration.");
            var runtime = load.Assemblies.Single(a => a.GetName().Name == "Durevo.Runtime");
            Check(runtime.Location == Path.Combine(package, "Managed", "Durevo.Runtime.dll"), "Host runtime was used.");
            object runtimeRelease = runtime.GetType("Durevo.Runtime.SignedRelease", true)!.GetMethod("Verify")!.Invoke(null,
                [package, File.ReadAllBytes(Path.Combine(package, ReleaseInventory.ManifestName)), publicKey, plan.Product, plan.Revision])!;
            object runtimeImage = runtime.GetType("Durevo.Runtime.VerifiedNativeImage", true)!.GetMethod("Capture")!.Invoke(null,
                [runtimeRelease, package, plan.NativePath])!;
            using var verifiedBackend = (IDisposable)runtimeImage.GetType().GetMethod("Load")!.Invoke(runtimeImage, null)!;
            using (var lease = (IDisposable)runtime.GetType("Durevo.Runtime.EncryptedIntegerMachine", true)!
                .GetMethod("RegisterVerifiedNativeKey")!.Invoke(null, [key, verifiedBackend])!)
            foreach (string? sample in new string?[] { null, "", "say(a)", "say(a,b)", "say('a,b')", "say(f(1,2))", "say(f(1,2),3)", "say([1,2])", "say({1:2,3:4})", "say('😀,я',1)", "say('\0,\ud800')", "say(" })
                Check(Equals(Observe(parser, sample), Observe(baselineParser, sample)), "Packaged parser changed behavior.");
            Check(!load.NativeLoaded, "Verified binding fell back to name-based native loading.");
            Check(Equals(Observe(parser, "say(a,b)"), typeof(UnauthorizedAccessException).FullName), "Disposed key did not revoke new calls.");
            var cipher = load.LoadFromAssemblyPath(Path.Combine(package, "Managed", "JuniorCoder.LicenseKey.dll")).GetType("StringCipher", true)!;
            var baselineCipher = original.LoadFromAssemblyPath(Path.Combine(source, "Managed", "JuniorCoder.LicenseKey.dll")).GetType("StringCipher", true)!;
            const string text = "synthetic лицензия 😀", secret = "synthetic-pilot-secret";
            string Call(Type type, string method, string value) => (string)type.GetMethod(method)!.Invoke(null, [value, secret])!;
            Check(Call(cipher, "DecryptStringAES", Call(baselineCipher, "EncryptStringAES", text)) == text, "Packaged decrypt failed.");
            Check(Call(baselineCipher, "DecryptStringAES", Call(cipher, "EncryptStringAES", text)) == text, "Packaged encrypt failed.");
            var analyzer = load.LoadFromAssemblyPath(Path.Combine(package, "Managed", "CodeAnalyzer.dll"))
                .GetType("JuniorCoder.Scripts.CodeAnalyzer.PythonCodeChecker", true)!;
            foreach (var sample in new[] { ("up(1)", false), ("up(1", true), ("up1)", true) })
            {
                object value = analyzer.GetMethod("RunAnalyzer")!.Invoke(Activator.CreateInstance(analyzer), [sample.Item1])!;
                Check((bool)value.GetType().GetProperty("IsError")!.GetValue(value)! == sample.Item2, "Packaged analyzer failed.");
            }
            foreach (var module in modules)
                Check(module.InputSha256 == Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(
                    Path.Combine(snapshots, Path.GetFileName(module.Path))))), "Original cached game module changed.");
            File.WriteAllText(Path.Combine(evidence, "execution.json"), JsonSerializer.Serialize(new {
                Status = "PASS", Checks = checks, Build = built, Plan = plan,
                Scope = "Three cached game modules; not a full Player installation or update feed. Native and managed runtime loaded from package. Synthetic in-memory keys discarded."
            }, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"PASS: signed three-module JuniorCoder package, {checks} actual-method/publication checks.");
        }
        finally { original.Unload(); load.Unload(); CryptographicOperations.ZeroMemory(key); }
    }
}
