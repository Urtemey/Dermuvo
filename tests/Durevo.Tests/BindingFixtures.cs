using System.Security.Cryptography;
using Durevo.Core;
using Mono.Cecil;

internal static class BindingFixtures
{
    internal static void Write(string output)
    {
        foreach (string scenario in new[] { "resolver-first", "preload-signed", "preload-foreign", "session-hostile-resolver", "session-preloaded-foreign", "session-late-foreign" })
        {
            string directory = Path.Combine(output, scenario);
            string release = Path.Combine(directory, "release");
            if (Directory.Exists(directory)) throw new IOException("Binding fixture must be new.");
            var fixture = DependencyBoundaryProbe.CreateFixture(release);
            File.WriteAllBytes(Path.Combine(release, fixture.Dependency + ".dll"), fixture.Bytes);
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            File.WriteAllBytes(Path.Combine(directory, "manifest.bin"), ReleaseSigner.Create(release, "BindingProbe", 1, signer));
            File.WriteAllBytes(Path.Combine(directory, "public.bin"), LicenseIssuer.ExportPublicKey(signer));
            File.WriteAllText(Path.Combine(directory, "entry.txt"), fixture.Entry);
            File.WriteAllText(Path.Combine(directory, "dependency.txt"), fixture.Dependency);
            using var foreign = ModuleDefinition.ReadModule(new MemoryStream(fixture.Bytes));
            var method = foreign.Types.Single(t => t.Name == "Dependency").Methods.Single(m => m.Name == "Value");
            method.Body.Instructions[0].Operand = -999;
            // Preserve identity and MVID: comparing those alone cannot authenticate loaded code.
            foreign.Write(Path.Combine(directory, "foreign.bin"));
        }
    }
}
