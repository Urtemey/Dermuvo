using System.Diagnostics;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using Durevo.Core;
using Durevo.Fixture;
using Durevo.Runtime;

internal static class ProtectedReleaseCliSuite
{
    internal sealed class PackageContext(string managed, string? native, bool requireVerified = false) : AssemblyLoadContext(isCollectible: true)
    {
        internal bool NativeLoaded;
        protected override Assembly? Load(AssemblyName name)
        {
            if (name.Name is "Durevo.Runtime" or "BouncyCastle.Cryptography" or "Mono.Cecil")
                return LoadFromAssemblyPath(Path.Combine(managed, name.Name + ".dll"));
            return null;
        }
        protected override nint LoadUnmanagedDll(string name)
        {
            if (name is "kernel32.dll" or "libc.so.6" or "libdl.so.2") return IntPtr.Zero;
            if (name != "durevo_vm" || native == null || requireVerified) throw new DllNotFoundException("Unplanned native dependency: " + name);
            nint result = LoadUnmanagedDllFromPath(native);
            NativeLoaded = true;
            return result;
        }
    }
    internal static int Run(string temporaryRoot, string cli, string privateKey, string password,
        string publicKey, string programKeyFile, byte[] programKey)
    {
        string source = Path.Combine(temporaryRoot, "cli-build-input");
        Directory.CreateDirectory(Path.Combine(source, "Managed"));
        string module = Path.Combine(source, "Managed", "fixture.dll");
        File.Copy(typeof(Cases).Assembly.Location, module);
        string planFile = Path.Combine(temporaryRoot, "build-plan.json");
        var selection = new ReleaseModulePlan("Managed/fixture.dll", Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(module))),
            "vm-encrypted", ["System.Int32 Durevo.Fixture.Cases::Arithmetic(System.Int32,System.Int32)"]);
        var plan = new ProtectedReleasePlan(1, "Release-Build-Test", 23, "Managed", null, [selection]);
        int checks = 0;
        void Check(bool condition, string message) { checks++; if (!condition) throw new Exception(message); }
        (int Code, string Text) Run(params string[] arguments)
        {
            var info = new ProcessStartInfo("dotnet") { UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true };
            info.ArgumentList.Add(cli);
            foreach (string argument in arguments) info.ArgumentList.Add(argument);
            info.Environment["DUREVO_KEY_PASSWORD"] = password;
            using var process = Process.Start(info)!;
            var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(30000)) { process.Kill(entireProcessTree: true); throw new TimeoutException("Release build CLI timed out."); }
            string text = stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult();
            if (text.Contains(password, StringComparison.Ordinal) || text.Contains(Convert.ToBase64String(programKey), StringComparison.Ordinal))
                throw new Exception("Build command printed a secret.");
            return (process.ExitCode, text);
        }
        void Save(ProtectedReleasePlan value) => File.WriteAllText(planFile, JsonSerializer.Serialize(value));
        void Execute(string output, bool nativeMode, bool verifiedMode = false)
        {
            string managed = Path.Combine(output, "Managed");
            string? nativePath = nativeMode ? Path.Combine(output, plan.NativePath!.Replace('/', Path.DirectorySeparatorChar)) : null;
            var load = new PackageContext(managed, nativePath, verifiedMode);
            try
            {
                var assembly = load.LoadFromAssemblyPath(Path.Combine(managed, "fixture.dll"));
                var method = assembly.GetType(typeof(Cases).FullName!)!.GetMethod("Arithmetic")!;
                bool denied = false;
                try { method.Invoke(null, [1, 3]); } catch (TargetInvocationException error) when (error.InnerException is UnauthorizedAccessException) { denied = true; }
                Check(denied, "Packaged encrypted method ran without activation.");
                var runtime = load.Assemblies.Single(a => a.GetName().Name == "Durevo.Runtime");
                Check(runtime.Location == Path.Combine(managed, "Durevo.Runtime.dll"), "Executed host runtime instead of published runtime.");
                var engine = runtime.GetType("Durevo.Runtime.EncryptedIntegerMachine", true)!;
                using var backend = verifiedMode ? (IDisposable)CreateBackend() : null;
                object CreateBackend() {
                    object release = runtime.GetType("Durevo.Runtime.SignedRelease", true)!.GetMethod("Verify")!.Invoke(null,
                        [output, File.ReadAllBytes(Path.Combine(output, ReleaseInventory.ManifestName)), File.ReadAllBytes(publicKey), plan.Product, plan.Revision])!;
                    object image = runtime.GetType("Durevo.Runtime.VerifiedNativeImage", true)!.GetMethod("Capture")!.Invoke(null, [release, output, plan.NativePath])!;
                    return image.GetType().GetMethod("Load")!.Invoke(image, null)!;
                }
                using (var lease = (IDisposable)engine.GetMethod(verifiedMode ? "RegisterVerifiedNativeKey" : nativeMode ? "RegisterNativeKey" : "RegisterKey")!
                    .Invoke(null, verifiedMode ? [programKey, backend] : [programKey])!)
                foreach (int value in new[] { 0, 1, -1, int.MinValue, int.MaxValue })
                    Check(Equals(method.Invoke(null, [value, 3]), Cases.Arithmetic(value, 3)), "Published VM method changed behavior.");
                if (nativeMode) Check(verifiedMode ? !load.NativeLoaded : load.NativeLoaded, "Native binding used the wrong loading path.");
                else Check(load.Assemblies.Any(a => a.GetName().Name == "BouncyCastle.Cryptography" &&
                    a.Location == Path.Combine(managed, "BouncyCastle.Cryptography.dll")), "Published crypto dependency was not used.");
                denied = false;
                try { method.Invoke(null, [1, 3]); } catch (TargetInvocationException error) when (error.InnerException is UnauthorizedAccessException) { denied = true; }
                Check(denied, "Disposed package activation still executed.");
            } finally { load.Unload(); }
        }
        // Keyring publication and execution use the packaged runtime, not the host copy.
        byte[] secondKey = RandomNumberGenerator.GetBytes(32);
        string secondKeyFile = Path.Combine(temporaryRoot, "second.vmkey");
        File.WriteAllBytes(secondKeyFile, secondKey);
        string keyringFile = Path.Combine(temporaryRoot, "keyring.json");
        string branch = "System.Int32 Durevo.Fixture.Cases::Branches(System.Int32)";
        var slots = new Dictionary<string, string> { [selection.Methods[0]] = "arithmetic", [branch] = "branches" };
        var keyPlan = plan with { KeyFeatures = new() { ["arithmetic"] = 1, ["branches"] = 2 }, Modules = [selection with { Methods = [selection.Methods[0], branch], KeySlots = slots }] };
        var keyPaths = new Dictionary<string, string> {
            ["arithmetic"] = Path.GetRelativePath(temporaryRoot, programKeyFile),
            ["branches"] = Path.GetFileName(secondKeyFile)
        };
        void SaveKeys(Dictionary<string, string> paths) => File.WriteAllText(keyringFile, JsonSerializer.Serialize(paths));
        SaveKeys(keyPaths); Save(keyPlan);
        string keyOutput = Path.Combine(temporaryRoot, "cli-keyring-release");
        var keyBuilt = Run("protect-release-keyring", source, keyOutput, planFile, privateKey, keyringFile);
        Check(keyBuilt.Code == 0, "Keyring release failed: " + keyBuilt.Text);
        Check(!keyBuilt.Text.Contains(Convert.ToBase64String(secondKey)), "CLI printed second key.");
        Check(Run("verify-release", keyOutput, publicKey, plan.Product, "23").Code == 0, "Keyring signature failed.");
        using (var report = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(keyOutput, ProtectedReleaseBuilder.ReportName))))
        {
            Check(report.RootElement.GetProperty("KeySlots").GetProperty("branches").GetString() ==
                EncryptedIntegerMachine.IdentifyKey(secondKey), "Report lost slot identity.");
            Check(report.RootElement.GetProperty("Modules")[0].GetProperty("KeySlots").GetProperty(branch).GetString() == "branches",
                "Report lost method assignment.");
        }
        foreach (string file in Directory.EnumerateFiles(keyOutput, "*", SearchOption.AllDirectories))
        {
            byte[] bytes = File.ReadAllBytes(file);
            Check(bytes.AsSpan().IndexOf(programKey) < 0 && bytes.AsSpan().IndexOf(secondKey) < 0, "Packaged raw key.");
        }
        using var policySigner = ECDsa.Create();
        policySigner.ImportFromEncryptedPem(File.ReadAllText(privateKey), password);
        byte[] featureLicense = LicenseIssuer.Issue(policySigner,
            new LicenseClaims("policy-license", plan.Product, "policy-device", 1000, 3000, 1, 1));
        string featureTicketFile = Path.Combine(temporaryRoot, "policy-license.bin");
        File.WriteAllBytes(featureTicketFile, featureLicense);
        string featureGrantFile = Path.Combine(temporaryRoot, "policy-grant.bin");
        var policyIssued = Run("issue-release-grant", keyOutput, "arithmetic", featureTicketFile, programKeyFile,
            privateKey, plan.Product, "23", featureGrantFile);
        Check(policyIssued.Code == 0, "Signed-policy grant failed: " + policyIssued.Text);
        byte[] featureGrant = File.ReadAllBytes(featureGrantFile);
        Check(BitConverter.ToUInt64(featureGrant, 72) == 1, "Grant did not use signed feature mask.");
        int failedPolicy = 0;
        void RejectPolicy(string slot = "branches", string? keyFile = null, string? product = null, string floor = "23")
        {
            string deniedPath = Path.Combine(temporaryRoot, "denied-policy-" + failedPolicy++ + ".bin");
            var denied = Run("issue-release-grant", keyOutput, slot, featureTicketFile, keyFile ?? secondKeyFile,
                privateKey, product ?? plan.Product, floor, deniedPath);
            Check(denied.Code != 0 && !File.Exists(deniedPath), "Invalid policy issuance published a grant.");
        }
        RejectPolicy(); // valid B key but ticket has only feature A
        RejectPolicy("arithmetic"); // B key cannot impersonate A
        RejectPolicy("absent");
        RejectPolicy("arithmetic", programKeyFile, "other-product");
        RejectPolicy("arithmetic", programKeyFile, floor: "24");
        var wrongProductLicense = LicenseIssuer.Issue(policySigner,
            new LicenseClaims("other", "OtherProduct", "policy-device", 1000, 3000, 3, 1));
        File.WriteAllBytes(featureTicketFile, wrongProductLicense);
        RejectPolicy("arithmetic", programKeyFile);
        File.WriteAllBytes(featureTicketFile, featureLicense);
        string policyReportPath = Path.Combine(keyOutput, ProtectedReleaseBuilder.ReportName);
        byte[] savedReport = File.ReadAllBytes(policyReportPath);
        File.AppendAllText(policyReportPath, " ");
        RejectPolicy("arithmetic", programKeyFile); // report tampering before issuance
        File.WriteAllBytes(policyReportPath, savedReport);
        Check(Run("issue-release-grant", keyOutput, "arithmetic", featureTicketFile, programKeyFile,
            privateKey, plan.Product, "23", featureGrantFile).Code != 0 &&
            File.ReadAllBytes(featureGrantFile).SequenceEqual(featureGrant), "Grant overwrite changed prior output.");
        var keyLoad = new PackageContext(Path.Combine(keyOutput, "Managed"), null);
        try
        {
            var type = keyLoad.LoadFromAssemblyPath(Path.Combine(keyOutput, "Managed", "fixture.dll")).GetType(typeof(Cases).FullName!)!;
            object? Call(string name, params object[] values)
            {
                try { return type.GetMethod(name)!.Invoke(null, values); }
                catch (TargetInvocationException e) { return e.InnerException!.GetType(); }
            }
            Check(Equals(Call("Branches", 9), typeof(UnauthorizedAccessException)), "B executed without keys.");
            var runtime = keyLoad.Assemblies.Single(a => a.GetName().Name == "Durevo.Runtime");
            Check(runtime.Location == Path.Combine(keyOutput, "Managed", "Durevo.Runtime.dll"), "Keyring test used host runtime.");
            var register = runtime.GetType("Durevo.Runtime.EncryptedIntegerMachine")!.GetMethod("RegisterKey")!;
            using var first = (IDisposable)runtime.GetType("Durevo.Runtime.ProgramKeyGrant")!.GetMethod("Activate")!.Invoke(null,
                [featureGrant, featureLicense, programKey, File.ReadAllBytes(publicKey),
                 EncryptedIntegerMachine.IdentifyKey(programKey), plan.Product, "policy-device", (ulong)0, (uint)1,
                 (Func<DateTimeOffset>)(() => DateTimeOffset.FromUnixTimeSeconds(1500))])!;
            Check(Equals(Call("Arithmetic", 1, 3), Cases.Arithmetic(1, 3)), "Key A execution mismatch.");
            Check(Equals(Call("Branches", 9), typeof(UnauthorizedAccessException)), "Key A unlocked B.");
            using var second = (IDisposable)register.Invoke(null, [secondKey])!;
            Check(Equals(Call("Branches", 9), Cases.Branches(9)), "Key B execution mismatch.");
            first.Dispose();
            Check(Equals(Call("Arithmetic", 1, 3), typeof(UnauthorizedAccessException)), "Disposed A still works.");
            Check(Equals(Call("Branches", 9), Cases.Branches(9)), "A disposal revoked B.");
        }
        finally { keyLoad.Unload(); }
        int keyRejected = 0;
        void RejectKeys(ProtectedReleasePlan candidate, Dictionary<string, string> paths)
        {
            Save(candidate); SaveKeys(paths);
            string destination = Path.Combine(temporaryRoot, "rejected-keyring-" + keyRejected++);
            var attempt = Run("protect-release-keyring", source, destination, planFile, privateKey, keyringFile);
            Check(attempt.Code != 0 && !Directory.Exists(destination), "Invalid keyring published output.");
            Check(!Directory.EnumerateDirectories(temporaryRoot, ".durevo-build-*").Any(), "Keyring failure left staging.");
            Check(!attempt.Text.Contains(Convert.ToBase64String(secondKey)), "Failure printed second key.");
        }
        RejectKeys(keyPlan with { KeyFeatures = null }, keyPaths);
        RejectKeys(keyPlan with { KeyFeatures = new() { ["arithmetic"] = 1 } }, keyPaths);
        RejectKeys(plan, keyPaths); // missing assignments
        RejectKeys(keyPlan, new(keyPaths) { ["branches"] = keyPaths["arithmetic"] }); // same key in distinct slots
        RejectKeys(keyPlan, new() { ["arithmetic"] = keyPaths["arithmetic"] }); // missing key
        RejectKeys(keyPlan, new(keyPaths) { ["unused"] = keyPaths["arithmetic"] });
        RejectKeys(keyPlan with { Modules = [selection with { KeySlots = slots }] }, keyPaths); // extra method mapping
        RejectKeys(keyPlan with { Modules = [selection with { Mode = "obfuscate", KeySlots = slots }], RuntimeDirectory = null }, keyPaths);
        RejectKeys(keyPlan, new(keyPaths) { ["branches"] = module }); // control inside source
        string renamed = Path.Combine(source, "renamed-key-secret.bin");
        File.Copy(secondKeyFile, renamed);
        RejectKeys(keyPlan, keyPaths);
        File.Delete(renamed);
        Save(keyPlan);
        File.WriteAllText(keyringFile, "{\"arithmetic\":" + JsonSerializer.Serialize(keyPaths["arithmetic"]) + ",\"arithmetic\":" + JsonSerializer.Serialize(keyPaths["arithmetic"]) + "}");
        string duplicateOutput = Path.Combine(temporaryRoot, "duplicate-keyring");
        Check(Run("protect-release-keyring", source, duplicateOutput, planFile, privateKey, keyringFile).Code != 0 &&
            !Directory.Exists(duplicateOutput), "Duplicate JSON keyring slots accepted.");
        CryptographicOperations.ZeroMemory(secondKey);
        Save(plan);
        string output = Path.Combine(temporaryRoot, "cli-protected-release");
        var built = Run("protect-release", source, output, planFile, privateKey, programKeyFile);
        Check(built.Code == 0, "Protected release build failed: " + built.Text);
        Check(Run("verify-release", output, publicKey, plan.Product, "23").Code == 0, "New release signature failed.");
        Execute(output, false);
        foreach (string file in Directory.EnumerateFiles(output, "*", SearchOption.AllDirectories))
            Check(File.ReadAllBytes(file).AsSpan().IndexOf(programKey) < 0, "Build leaked the program key.");
        byte[] manifest = File.ReadAllBytes(Path.Combine(output, ReleaseInventory.ManifestName));
        Check(Run("protect-release", source, output, planFile, privateKey, programKeyFile).Code != 0 &&
            manifest.SequenceEqual(File.ReadAllBytes(Path.Combine(output, ReleaseInventory.ManifestName))), "Build overwrote an existing release.");

        int sequence = 0;
        void Reject(ProtectedReleasePlan value, bool passKey = true)
        {
            Save(value);
            string target = Path.Combine(temporaryRoot, "bad-cli-build-" + sequence++);
            string[] arguments = ["protect-release", source, target, planFile, privateKey];
            if (passKey) arguments = arguments.Append(programKeyFile).ToArray();
            Check(Run(arguments).Code != 0 && !Directory.Exists(target), "Invalid build published a release.");
            Check(!Directory.EnumerateDirectories(temporaryRoot, ".durevo-build-*").Any(), "Failed CLI left staging files.");
        }
        Reject(plan, passKey: false);
        Reject(plan with { Modules = [selection with { InputSha256 = new string('0', 64) }] });
        Reject(plan with { Modules = [selection with { Methods = ["System.Int32 Durevo.Fixture.Cases::Unsupported(System.Int32)"] }] });
        Reject(plan with { RuntimeDirectory = "Elsewhere" });
        File.Copy(programKeyFile, Path.Combine(source, "renamed-active-secret.bin"));
        Reject(plan); File.Delete(Path.Combine(source, "renamed-active-secret.bin"));
        File.WriteAllText(Path.Combine(source, "Managed", "Durevo.Runtime.dll"), "stale runtime");
        Reject(plan); File.Delete(Path.Combine(source, "Managed", "Durevo.Runtime.dll"));
        Save(plan);
        File.WriteAllText(planFile, File.ReadAllText(planFile).Replace("\"Version\":1", "\"Typo\":1,\"Version\":1"));
        string badPlanOutput = Path.Combine(temporaryRoot, "bad-schema-release");
        Check(Run("protect-release", source, badPlanOutput, planFile, privateKey, programKeyFile).Code != 0 &&
            !Directory.Exists(badPlanOutput), "Unknown plan property accepted.");
        string nativeName = OperatingSystem.IsWindows() ? "durevo_vm.dll" : "libdurevo_vm.so";
        string nativeFile = Path.Combine(AppContext.BaseDirectory, nativeName);
        if (File.Exists(nativeFile))
        {
            plan = plan with { NativePath = "Plugins/x86_64/" + nativeName,
                Modules = [selection with { Mode = "vm-encrypted-native" }] };
            Save(plan);
            string badNativeDirectory = Path.Combine(temporaryRoot, "bad-native-input");
            Directory.CreateDirectory(badNativeDirectory);
            string badNative = Path.Combine(badNativeDirectory, nativeName);
            foreach (byte[] bytes in new[] { new byte[64], File.ReadAllBytes(typeof(Cases).Assembly.Location) })
            {
                File.WriteAllBytes(badNative, bytes);
                string rejected = Path.Combine(temporaryRoot, "bad-native-release-" + sequence++);
                var attempt = Run("protect-release", source, rejected, planFile, privateKey, programKeyFile, badNative);
                Check(attempt.Code != 0 && !Directory.Exists(rejected), "Non-native backend was signed/published.");
            }
            string nativeOutput = Path.Combine(temporaryRoot, "cli-native-release");
            built = Run("protect-release", source, nativeOutput, planFile, privateKey, programKeyFile, nativeFile);
            Check(built.Code == 0, "Native release build failed: " + built.Text);
            Check(Run("verify-release", nativeOutput, publicKey, plan.Product, "23").Code == 0, "Native release signature failed.");
            Execute(nativeOutput, true);
            string packagedNative = Path.Combine(nativeOutput, plan.NativePath.Replace('/', Path.DirectorySeparatorChar));
            Check(SHA256.HashData(File.ReadAllBytes(packagedNative)).SequenceEqual(SHA256.HashData(File.ReadAllBytes(nativeFile))),
                "Native artifact changed while packaging.");
            plan = plan with { Modules = [selection with { Mode = "vm-encrypted-verified-native" }] };
            Save(plan);
            string verifiedOutput = Path.Combine(temporaryRoot, "cli-verified-native-release");
            built = Run("protect-release", source, verifiedOutput, planFile, privateKey, programKeyFile, nativeFile);
            Check(built.Code == 0, "Verified native package failed: " + built.Text);
            Execute(verifiedOutput, true, true);
        }
        string tamperedOutput = Path.Combine(temporaryRoot, "tampered-package-copy");
        foreach (string file in Directory.EnumerateFiles(output, "*", SearchOption.AllDirectories))
        {
            string target = Path.Combine(tamperedOutput, Path.GetRelativePath(output, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target);
        }
        File.WriteAllText(Path.Combine(tamperedOutput, "Managed", "fixture.dll"), "tamper");
        Check(Run("verify-release", tamperedOutput, publicKey, "Release-Build-Test", "23").Code != 0, "Transformed DLL tamper was accepted.");
        Check(selection.InputSha256 == Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(module))), "CLI changed source.");
        Console.WriteLine($"Protected release CLI suite: {checks} publication and packaged-runtime checks.");
        return checks;
    }
}
