using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Fixture;
using Durevo.Runtime;

internal static class ReleaseBuildSuite
{
    internal static int Run(string root)
    {
        int checks = 0;
        void Check(bool value, string message) { checks++; if (!value) throw new Exception(message); }
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string source = Path.Combine(root, "build-input"), output = Path.Combine(root, "build-output");
        Directory.CreateDirectory(Path.Combine(source, "Managed"));
        Directory.CreateDirectory(Path.Combine(source, "empty-required"));
        File.Copy(typeof(Cases).Assembly.Location, Path.Combine(source, "Managed", "fixture.dll"));
        File.WriteAllText(Path.Combine(source, "Managed", "fixture.pdb"), "stale selected symbols");
        File.WriteAllText(Path.Combine(source, "Managed", "fixture.dll.mdb"), "stale selected symbols");
        File.WriteAllText(Path.Combine(source, "unselected.pdb"), "keep unselected file");
        File.WriteAllBytes(Path.Combine(source, "launcher"), [11, 23, 45]);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(Path.Combine(source, "launcher"),
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var original = ReleaseInventory.Capture(source);
        var selected = new ReleaseModulePlan("Managed/fixture.dll",
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(source, "Managed", "fixture.dll")))),
            "obfuscate", ["System.Int32 Durevo.Fixture.Cases::Arithmetic(System.Int32,System.Int32)"]);
        var plan = new ProtectedReleasePlan(1, "JuniorCoder-Test", 17, null, null, [selected]);
        var result = ProtectedReleaseBuilder.Build(source, output, plan, signer);
        var verified = SignedRelease.Verify(output, File.ReadAllBytes(Path.Combine(output, ReleaseInventory.ManifestName)),
            LicenseIssuer.ExportPublicKey(signer), plan.Product, 17);
        Check(result.Modules == 1 && result.Files == verified.Files.Count, "Build result does not match signature.");
        Check(File.Exists(Path.Combine(output, ProtectedReleaseBuilder.ReportName)), "Build report absent.");
        Check(!File.Exists(Path.Combine(output, "Managed", "fixture.pdb")) &&
            !File.Exists(Path.Combine(output, "Managed", "fixture.dll.mdb")), "Stale selected symbols shipped.");
        Check(File.ReadAllText(Path.Combine(output, "unselected.pdb")) == "keep unselected file", "Unselected file changed.");
        Check(File.ReadAllBytes(Path.Combine(output, "launcher")).SequenceEqual(new byte[] { 11, 23, 45 }), "Launcher changed.");
        Check(Directory.Exists(Path.Combine(output, "empty-required")), "Required empty directory was lost.");
        if (!OperatingSystem.IsWindows()) Check(File.GetUnixFileMode(Path.Combine(source, "launcher")) ==
            File.GetUnixFileMode(Path.Combine(output, "launcher")), "Executable mode changed.");
        var load = new AssemblyLoadContext("release-build", true);
        try {
            var type = load.LoadFromAssemblyPath(Path.Combine(output, "Managed", "fixture.dll")).GetType(typeof(Cases).FullName!)!;
            foreach (int value in new[] { 0, 1, -1, int.MinValue, int.MaxValue })
                Check(Equals(type.GetMethod("Arithmetic")!.Invoke(null, [value, 13]), Cases.Arithmetic(value, 13)),
                    "Published transformed method changed behavior.");
        } finally { load.Unload(); }

        int denied = 0;
        void Reject(ProtectedReleasePlan rejected, string? destination = null, IReadOnlyList<ReleaseBuildAsset>? assets = null,
            IReadOnlyCollection<string>? secretHashes = null, ECDsa? authority = null)
        {
            string target = destination ?? Path.Combine(root, "rejected-build-" + denied++);
            bool existed = Directory.Exists(target);
            try { ProtectedReleaseBuilder.Build(source, target, rejected, authority ?? signer, assets: assets, forbiddenFileHashes: secretHashes); }
            catch (Exception e) when (e is ArgumentException or IOException or InvalidDataException or NotSupportedException or CryptographicException) {
                Check(existed || !Directory.Exists(target), "Failed build published output.");
                Check(!Directory.EnumerateDirectories(root, ".durevo-build-*").Any(), "Failed build left staging payload.");
                return;
            }
            throw new Exception("Invalid release build accepted.");
        }
        Reject(plan, output); Reject(plan, source); Reject(plan, Path.Combine(source, "nested"));
        Reject(plan with { Version = 2 });
        Reject(plan with { Revision = 0 });
        Reject(plan with { Product = "" });
        Reject(plan with { Modules = [] });
        Reject(plan with { Modules = [selected, selected] });
        Reject(plan with { Modules = [selected with { Path = "../escape.dll" }] });
        Reject(plan with { Modules = [selected with { InputSha256 = new string('0', 64) }] });
        Reject(plan with { Modules = [selected with { Methods = ["absent"] }] });
        Reject(plan with { Modules = [selected with { Mode = "unknown" }] });
        Reject(plan with { Modules = [selected with { Mode = "vm-encrypted" }], RuntimeDirectory = "Managed" });
        Reject(plan, assets: [new("unexpected.bin", [1])]);
        Reject(plan, secretHashes: [selected.InputSha256]);
        using (var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384)) Reject(plan, authority: wrongCurve);
        File.WriteAllText(Path.Combine(source, ProtectedReleaseBuilder.ReportName), "stale");
        Reject(plan); File.Delete(Path.Combine(source, ProtectedReleaseBuilder.ReportName));
        File.WriteAllText(Path.Combine(source, ReleaseInventory.ManifestName), "stale");
        Reject(plan); File.Delete(Path.Combine(source, ReleaseInventory.ManifestName));
        if (!OperatingSystem.IsWindows())
        {
            string link = Path.Combine(source, "linked");
            File.CreateSymbolicLink(link, Path.Combine(source, "launcher"));
            Reject(plan); File.Delete(link);
            string outputLink = Path.Combine(root, "output-link");
            Directory.CreateSymbolicLink(outputLink, source);
            Reject(plan, Path.Combine(outputLink, "new"));
            Directory.Delete(outputLink);
        }
        var after = ReleaseInventory.Capture(source);
        Check(original.Count == after.Count && original.Zip(after).All(p => p.First.Path == p.Second.Path &&
            p.First.Sha256.SequenceEqual(p.Second.Sha256)), "Build or rejection mutated input.");
        File.AppendAllText(Path.Combine(output, ProtectedReleaseBuilder.ReportName), "tamper");
        bool tampered = false;
        try { SignedRelease.Verify(output, File.ReadAllBytes(Path.Combine(output, ReleaseInventory.ManifestName)),
            LicenseIssuer.ExportPublicKey(signer), plan.Product, 17); } catch (InvalidDataException) { tampered = true; }
        Check(tampered, "Build report is not authenticated.");
        Check(ProtectedReleaseBuilder.ContainsPath(Path.GetPathRoot(source)!, source), "Volume-root containment broken.");
        Console.WriteLine($"Protected release builder suite: {checks} transaction/signature/content checks.");
        return checks;
    }
}
