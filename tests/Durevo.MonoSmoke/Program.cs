using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using Durevo.Runtime;

internal static class MonoSmoke
{
    private static void Reject(Action action)
    {
        try { action(); }
        catch (CryptographicException) { return; }
        catch (InvalidDataException) { return; }
        catch (UnauthorizedAccessException) { return; }
        throw new Exception("Invalid signature or changed file was accepted.");
    }
    public static int Main(string[] args)
    {
        try
        {
            string root = args[0];
            Console.WriteLine("Runtime: " + Environment.Version + "; pointer size: " + IntPtr.Size);
            byte[] ticket = File.ReadAllBytes(Path.Combine(root, "ticket.bin"));
            byte[] key = File.ReadAllBytes(Path.Combine(root, "public.bin"));
            Func<byte[], LicenseClaims> verify = value => OfflineLicense.Verify(value, key,
                "Durevo.TestProduct", "synthetic-test-device", 1, 1, DateTimeOffset.FromUnixTimeSeconds(1500000));
            if (verify(ticket).Id != "cross-platform-test") throw new Exception("License claim mismatch.");
            byte[] corrupt = (byte[])ticket.Clone(); corrupt[corrupt.Length - 1] ^= 1;
            Reject(() => verify(corrupt));
            Array.Clear(corrupt, corrupt.Length - 64, 64);
            Reject(() => verify(corrupt));
            Console.WriteLine("PASS: valid, modified and zero P-256 signatures under Unity bundled Mono.");

            string releaseRoot = Path.Combine(root, "release");
            byte[] manifest = File.ReadAllBytes(Path.Combine(root, "manifest.bin"));
            byte[] releaseKey = File.ReadAllBytes(Path.Combine(root, "release-public.bin"));
            var release = SignedRelease.Verify(releaseRoot, manifest, releaseKey, "BoundaryProbe", 1);
            string entryName = File.ReadAllText(Path.Combine(root, "entry.txt"));
            string dependencyName = File.ReadAllText(Path.Combine(root, "dependency.txt"));
            Reject(() => VerifiedManagedGraph.Capture(release, releaseRoot, new[] { entryName + ".dll" },
                new[] { Assembly.Load("mscorlib").GetName() }));
            Console.WriteLine("PASS: graph preflight rejected the unsigned dependency without executing it.");
            var image = VerifiedManagedImage.Capture(release, releaseRoot, entryName + ".dll");
            string entryPath = Path.Combine(releaseRoot, entryName + ".dll");
            byte[] altered = File.ReadAllBytes(entryPath); altered[altered.Length / 2] ^= 1;
            File.WriteAllBytes(entryPath, altered);
            Reject(() => VerifiedManagedImage.Capture(release, releaseRoot, entryName + ".dll"));
            File.Delete(entryPath);
            int resolutions = 0;
            ResolveEventHandler resolver = (_, eventArgs) => {
                if (new AssemblyName(eventArgs.Name).Name != dependencyName) return null;
                resolutions++;
                return Assembly.Load(File.ReadAllBytes(Path.Combine(root, "unsigned-dependency.bin")));
            };
            AppDomain.CurrentDomain.AssemblyResolve += resolver;
            try {
                var assembly = image.Load();
                var result = assembly.GetType("Probe.Entry").GetMethod("Run").Invoke(null, null);
                if (!Equals(result, 31337) || resolutions != 1 || assembly.Location != "")
                    throw new Exception("Unexpected dependency resolution/snapshot behavior.");
            }
            finally { AppDomain.CurrentDomain.AssemblyResolve -= resolver; }
            Console.WriteLine("PASS: signed image bytes loaded after source tamper and deletion.");
            Console.WriteLine("KNOWN GAP: signed image invoked an unsigned dependency under Unity bundled Mono.");
            BindingProbe.Run(root);
            EncryptedProbe.Run(root);
            ExceptionProbe.Run(root);
            VerifiedNativeProbe.Run(root);
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
