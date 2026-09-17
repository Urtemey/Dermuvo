using System.Reflection;
using System.Security.Cryptography;
using Durevo.Core;
using Durevo.Runtime;
using Mono.Cecil;

internal static class ManagedGraphSuite
{
    internal static int Run(string temporaryRoot)
    {
        string root = Path.Combine(temporaryRoot, "managed-graph");
        var fixture = DependencyBoundaryProbe.CreateFixture(root);
        string entry = fixture.Entry + ".dll", dependency = fixture.Dependency + ".dll";
        string[] paths = [entry, dependency];
        AssemblyName[] hosts = [Assembly.Load("mscorlib").GetName()];
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        VerifiedRelease Sign() => SignedRelease.Verify(root, ReleaseSigner.Create(root, "GraphTest", 1, signer),
            LicenseIssuer.ExportPublicKey(signer), "GraphTest", 1);
        int count = 0;
        void Check(bool condition, string message) { count++; if (!condition) throw new Exception(message); }
        void Reject(Action action, string message)
        {
            bool rejected = false;
            try { action(); }
            catch (Exception error) when (error is UnauthorizedAccessException or InvalidDataException
                or CryptographicException or ArgumentException or NotSupportedException) { rejected = true; }
            Check(rejected, message);
        }
        var incomplete = Sign();
        Reject(() => VerifiedManagedGraph.Capture(incomplete, root, [entry], hosts),
            "Unsigned dependency passed preflight.");
        Check(!AppDomain.CurrentDomain.GetAssemblies().Any(a => a.GetName().Name == fixture.Entry),
            "Preflight executed/loaded application code.");

        File.WriteAllBytes(Path.Combine(root, dependency), fixture.Bytes);
        var complete = Sign();
        Reject(() => VerifiedManagedGraph.Capture(complete, root, [entry], hosts),
            "Signed but uncaptured dependency passed preflight.");
        Reject(() => VerifiedManagedGraph.Capture(complete, root, paths, []), "Implicit framework trust allowed.");
        Reject(() => VerifiedManagedGraph.Capture(complete, root, paths, hosts, 1), "Graph budget ignored.");
        Reject(() => VerifiedManagedGraph.Capture(complete, root, [entry, entry], hosts), "Duplicate path accepted.");
        var graph = VerifiedManagedGraph.Capture(complete, root, paths, hosts);
        Reject(() => graph.BindMono([Assembly.Load("mscorlib")]), "Mono binding accepted an untested non-Mono runtime.");
        Check(graph.Paths.Count == 2 && graph.Product == "GraphTest", "Incomplete captured graph.");
        Reject(() => graph.LoadImageUsingHostResolution("outside.dll"), "Uncaptured image loaded.");

        string duplicate = Path.Combine(root, "duplicate.dll");
        File.WriteAllBytes(duplicate, fixture.Bytes);
        Reject(() => VerifiedManagedGraph.Capture(Sign(), root, [entry, dependency, "duplicate.dll"], hosts),
            "Duplicate assembly identity accepted.");
        File.Delete(duplicate);
        var wrongHost = new AssemblyName(hosts[0].FullName) { Version = new Version(9, 0, 0, 0) };
        Reject(() => VerifiedManagedGraph.Capture(complete, root, paths, [wrongHost]), "Wrong host version accepted.");
        var shadow = new AssemblyName(fixture.Dependency + ", Version=0.0.0.0, Culture=neutral, PublicKeyToken=null");
        Reject(() => VerifiedManagedGraph.Capture(complete, root, paths, [hosts[0], shadow]),
            "Application/host collision accepted.");

        using (var module = ModuleDefinition.ReadModule(new MemoryStream(fixture.Bytes)))
        {
            module.Assembly.Name.Version = new Version(2, 0, 0, 0);
            module.Write(Path.Combine(root, dependency));
        }
        Reject(() => VerifiedManagedGraph.Capture(Sign(), root, paths, hosts), "Wrong application version accepted.");
        using (var module = ModuleDefinition.ReadModule(new MemoryStream(fixture.Bytes)))
        {
            module.ModuleReferences.Add(new ModuleReference("untrusted-native"));
            module.Write(Path.Combine(root, dependency));
        }
        Reject(() => VerifiedManagedGraph.Capture(Sign(), root, paths, hosts), "Native import escaped static policy.");
        File.WriteAllBytes(Path.Combine(root, dependency), fixture.Bytes);
        using (var module = ModuleDefinition.ReadModule(new MemoryStream(fixture.Bytes)))
        {
            var initializer = new MethodDefinition(".cctor", Mono.Cecil.MethodAttributes.Static
                | Mono.Cecil.MethodAttributes.SpecialName | Mono.Cecil.MethodAttributes.RTSpecialName,
                module.TypeSystem.Void);
            initializer.Body.Instructions.Add(Mono.Cecil.Cil.Instruction.Create(Mono.Cecil.Cil.OpCodes.Ret));
            module.Types[0].Methods.Add(initializer);
            module.Write(Path.Combine(root, dependency));
        }
        Reject(() => VerifiedManagedGraph.Capture(Sign(), root, paths, hosts), "Module initializer accepted during preload.");
        File.WriteAllBytes(Path.Combine(root, dependency), fixture.Bytes);
        var corrupt = (byte[])fixture.Bytes.Clone(); corrupt[corrupt.Length / 2] ^= 1;
        File.WriteAllBytes(Path.Combine(root, dependency), corrupt);
        Reject(() => VerifiedManagedGraph.Capture(complete, root, paths, hosts), "Dependency tamper after verification accepted.");

        // Both signed images must come from retained buffers, never changed/deleted disk paths.
        File.Delete(Path.Combine(root, entry));
        File.Delete(Path.Combine(root, dependency));
        int resolutions = 0;
        ResolveEventHandler resolver = (_, args) => {
            if (new AssemblyName(args.Name).Name != fixture.Dependency) return null;
            resolutions++;
            return graph.LoadImageUsingHostResolution(dependency);
        };
        AppDomain.CurrentDomain.AssemblyResolve += resolver;
        try
        {
            var assembly = graph.LoadImageUsingHostResolution(entry);
            var value = assembly.GetType("Probe.Entry")!.GetMethod("Run")!.Invoke(null, null);
            Check(Equals(value, 31337) && resolutions == 1, "Captured graph did not execute from signed images.");
        }
        finally { AppDomain.CurrentDomain.AssemblyResolve -= resolver; }
        Console.WriteLine($"Managed graph suite: {count} preflight/snapshot checks passed; host binding is not enforced.");
        return count;
    }
}
