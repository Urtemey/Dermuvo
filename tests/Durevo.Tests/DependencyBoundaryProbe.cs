using System.Reflection;
using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Runtime;
using Mono.Cecil;
using Mono.Cecil.Cil;

// Deliberately demonstrates a remaining attack, not a security-success test.
// Authenticating an entry DLL does not authenticate code supplied by host resolution.
internal static class DependencyBoundaryProbe
{
    internal static (string Entry, string Dependency, byte[] Bytes) CreateFixture(string root)
    {
        string suffix = Guid.NewGuid().ToString("N");
        string dependencyName = "UnsignedDependency" + suffix;
        string entryName = "SignedEntry" + suffix;
        Directory.CreateDirectory(root);
        byte[] dependency;
        using (var module = ModuleDefinition.CreateModule(dependencyName, ModuleKind.Dll))
        {
            var type = new TypeDefinition("Probe", "Dependency",
                Mono.Cecil.TypeAttributes.Public | Mono.Cecil.TypeAttributes.Abstract | Mono.Cecil.TypeAttributes.Sealed,
                module.TypeSystem.Object);
            module.Types.Add(type);
            var method = new MethodDefinition("Value",
                Mono.Cecil.MethodAttributes.Public | Mono.Cecil.MethodAttributes.Static, module.TypeSystem.Int32);
            type.Methods.Add(method);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 31337));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            using var buffer = new MemoryStream();
            module.Write(buffer);
            dependency = buffer.ToArray();
        }
        string entryPath = Path.Combine(root, entryName + ".dll");
        using (var module = ModuleDefinition.CreateModule(entryName, ModuleKind.Dll))
        {
            var reference = new AssemblyNameReference(dependencyName, new Version(0, 0, 0, 0));
            module.AssemblyReferences.Add(reference);
            var foreignType = new TypeReference("Probe", "Dependency", module, reference);
            var target = new MethodReference("Value", module.TypeSystem.Int32, foreignType) { HasThis = false };
            var type = new TypeDefinition("Probe", "Entry",
                Mono.Cecil.TypeAttributes.Public | Mono.Cecil.TypeAttributes.Abstract | Mono.Cecil.TypeAttributes.Sealed,
                module.TypeSystem.Object);
            module.Types.Add(type);
            var method = new MethodDefinition("Run",
                Mono.Cecil.MethodAttributes.Public | Mono.Cecil.MethodAttributes.Static, module.TypeSystem.Int32);
            type.Methods.Add(method);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.Write(entryPath);
        }
        return (entryName, dependencyName, dependency);
    }

    internal static void WriteMonoFixtures(string output, string? gameAssembly = null)
    {
        string root = Path.Combine(output, "release");
        if (Directory.Exists(root)) throw new IOException("Fixture directory must be new.");
        var fixture = CreateFixture(root);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllBytes(Path.Combine(output, "manifest.bin"), ReleaseSigner.Create(root, "BoundaryProbe", 1, signer));
        File.WriteAllBytes(Path.Combine(output, "release-public.bin"), LicenseIssuer.ExportPublicKey(signer));
        File.WriteAllBytes(Path.Combine(output, "unsigned-dependency.bin"), fixture.Bytes);
        File.WriteAllText(Path.Combine(output, "entry.txt"), fixture.Entry);
        File.WriteAllText(Path.Combine(output, "dependency.txt"), fixture.Dependency);
        BindingFixtures.Write(output);
        EncryptedFixtures.Write(output, gameAssembly);
        ExceptionFixtures.Write(output);
    }

    internal static int Run(string temporaryRoot)
    {
        string root = Path.Combine(temporaryRoot, "dependency-boundary");
        var (entryName, dependencyName, dependency) = CreateFixture(root);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifest = ReleaseSigner.Create(root, "BoundaryProbe", 1, signer);
        var release = SignedRelease.Verify(root, manifest, LicenseIssuer.ExportPublicKey(signer), "BoundaryProbe", 1);
        var snapshot = VerifiedManagedImage.Capture(release, root, entryName + ".dll");
        int resolutions = 0;
        ResolveEventHandler resolver = (_, args) =>
        {
            if (new AssemblyName(args.Name).Name != dependencyName) return null;
            resolutions++;
            return Assembly.Load(dependency);
        };
        AppDomain.CurrentDomain.AssemblyResolve += resolver;
        try
        {
            object? result = snapshot.Load().GetType("Probe.Entry")!.GetMethod("Run")!.Invoke(null, null);
            if (!Equals(result, 31337) || resolutions != 1 || release.Files.Count != 1)
                throw new Exception("Dependency boundary behavior changed: reassess loader trust model.");
        }
        finally { AppDomain.CurrentDomain.AssemblyResolve -= resolver; }
        Console.WriteLine("KNOWN GAP reproduced: signed entry executes an unsigned dependency supplied by host resolution.");
        return 1;
    }
}
