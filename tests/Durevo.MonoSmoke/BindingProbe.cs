using System;
using System.IO;
using System.Reflection;
using Durevo.Runtime;

internal static class BindingProbe
{
    internal static void Run(string root)
    {
        foreach (string scenario in new[] { "resolver-first", "preload-signed", "preload-foreign", "session-hostile-resolver", "session-preloaded-foreign", "session-late-foreign" })
        {
            string directory = Path.Combine(root, scenario);
            string releaseRoot = Path.Combine(directory, "release");
            string entry = File.ReadAllText(Path.Combine(directory, "entry.txt"));
            string dependency = File.ReadAllText(Path.Combine(directory, "dependency.txt"));
            var release = SignedRelease.Verify(releaseRoot, File.ReadAllBytes(Path.Combine(directory, "manifest.bin")),
                File.ReadAllBytes(Path.Combine(directory, "public.bin")), "BindingProbe", 1);
            var graph = VerifiedManagedGraph.Capture(release, releaseRoot,
                new[] { entry + ".dll", dependency + ".dll" }, new[] { Assembly.Load("mscorlib").GetName() });
            byte[] foreign = File.ReadAllBytes(Path.Combine(directory, "foreign.bin"));
            int foreignResolutions = 0, signedResolutions = 0;
            ResolveEventHandler first = (_, args) => {
                if (new AssemblyName(args.Name).Name != dependency) return null;
                foreignResolutions++;
                return Assembly.Load(foreign);
            };
            ResolveEventHandler second = (_, args) => {
                if (new AssemblyName(args.Name).Name != dependency) return null;
                signedResolutions++;
                return graph.LoadImageUsingHostResolution(dependency + ".dll");
            };
            if (scenario.StartsWith("session-", StringComparison.Ordinal))
            {
                AppDomain.CurrentDomain.AssemblyResolve += first;
                try
                {
                    if (scenario == "session-preloaded-foreign")
                    {
                        Assembly.Load(foreign);
                        bool rejected = false;
                        try { graph.BindMono(new[] { Assembly.Load("mscorlib") }); }
                        catch (UnauthorizedAccessException) { rejected = true; }
                        if (!rejected) throw new Exception("Session accepted a preloaded foreign identity.");
                        Console.WriteLine("PASS: session rejected preloaded foreign assembly.");
                        continue;
                    }
                    var session = graph.BindMono(new[] { Assembly.Load("mscorlib") });
                    if (scenario == "session-late-foreign")
                    {
                        Assembly.Load(foreign);
                        bool rejected = false;
                        try { session.GetAssembly(entry + ".dll"); }
                        catch (UnauthorizedAccessException) { rejected = true; }
                        if (!rejected) throw new Exception("Session missed a later identity collision.");
                        Console.WriteLine("PASS: session detected later foreign assembly.");
                        continue;
                    }
                    var assembly = session.GetAssembly(entry + ".dll");
                    var result = assembly.GetType("Probe.Entry").GetMethod("Run").Invoke(null, null);
                    if (!Equals(result, 31337) || foreignResolutions != 0)
                        throw new Exception("Foreign resolver won despite signed startup binding.");
                    Console.WriteLine("PASS: signed session executes verified dependency despite earlier hostile resolver.");
                    continue;
                }
                finally { AppDomain.CurrentDomain.AssemblyResolve -= first; }
            }
            if (scenario == "preload-foreign") Assembly.Load(foreign);
            if (scenario != "resolver-first") graph.LoadImageUsingHostResolution(dependency + ".dll");
            AppDomain.CurrentDomain.AssemblyResolve += first;
            AppDomain.CurrentDomain.AssemblyResolve += second;
            try
            {
                var loaded = graph.LoadImageUsingHostResolution(entry + ".dll");
                var result = loaded.GetType("Probe.Entry").GetMethod("Run").Invoke(null, null);
                if (!Equals(result, 31337) && !Equals(result, -999)) throw new Exception("Unexpected binding result.");
                Console.WriteLine("BINDING " + scenario + ": value=" + result +
                    "; foreignResolver=" + foreignResolutions + "; signedResolver=" + signedResolutions);
            }
            finally
            {
                AppDomain.CurrentDomain.AssemblyResolve -= second;
                AppDomain.CurrentDomain.AssemblyResolve -= first;
            }
        }
    }
}
