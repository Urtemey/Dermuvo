using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace Durevo.Runtime;

/// <summary>
/// Startup binding for Mono only. Requires a trusted, quiescent host: no concurrent
/// application assembly loading. Not a sandbox against arbitrary in-process code.
/// Assemblies remain loaded for the lifetime of the AppDomain.
/// </summary>
public sealed class VerifiedMonoSession
{
    private static readonly object StartupGate = new object();
    private readonly Dictionary<string, Assembly> byPath;
    private readonly Dictionary<string, Assembly> byName;
    private readonly Dictionary<string, Assembly> hosts;
    private VerifiedMonoSession(Dictionary<string, Assembly> paths, Dictionary<string, Assembly> names,
        Dictionary<string, Assembly> hosts)
    { byPath = paths; byName = names; this.hosts = hosts; }

    internal static VerifiedMonoSession Bind(VerifiedManagedGraph graph, IReadOnlyCollection<Assembly> trustedHosts)
    {
        if (Type.GetType("Mono.Runtime") is null)
            throw new PlatformNotSupportedException("VerifiedMonoSession requires tested Mono binding behavior.");
        if (trustedHosts is null) throw new ArgumentNullException(nameof(trustedHosts));
        lock (StartupGate)
        {
            var hosts = new Dictionary<string, Assembly>(StringComparer.OrdinalIgnoreCase);
            foreach (var host in trustedHosts)
            {
                if (host is null || host.IsDynamic || !hosts.TryAdd(host.GetName().Name!, host))
                    throw new ArgumentException("Invalid or duplicate trusted host assembly.");
            }
            foreach (var identity in graph.HostIdentities)
                if (!hosts.TryGetValue(identity.Key, out var host) ||
                    !string.Equals(host.FullName, identity.Value, StringComparison.OrdinalIgnoreCase))
                    throw new UnauthorizedAccessException("Required host identity is not explicitly pinned: " + identity.Key);

            foreach (var loaded in AppDomain.CurrentDomain.GetAssemblies())
            {
                string name = loaded.GetName().Name!;
                if (graph.ApplicationIdentities.ContainsKey(name))
                    throw new UnauthorizedAccessException("Application assembly already loaded: " + name);
                if (hosts.TryGetValue(name, out var host) && !ReferenceEquals(host, loaded))
                    throw new UnauthorizedAccessException("Trusted host identity collision: " + name);
            }
            // Capture has already authenticated every byte and rejected module initializers.
            // No application entry point is exposed until all images have been loaded.
            var paths = new Dictionary<string, Assembly>(StringComparer.Ordinal);
            var names = new Dictionary<string, Assembly>(StringComparer.OrdinalIgnoreCase);
            foreach (string path in graph.Paths)
            {
                var assembly = graph.LoadImageUsingHostResolution(path);
                var name = assembly.GetName().Name!;
                if (!graph.ApplicationIdentities.TryGetValue(name, out var expected) ||
                    !string.Equals(assembly.FullName, expected, StringComparison.OrdinalIgnoreCase) ||
                    assembly.Location.Length != 0 || !names.TryAdd(name, assembly))
                    throw new InvalidDataException("Unexpected result while binding signed images. Restart the host.");
                paths.Add(path, assembly);
            }
            var session = new VerifiedMonoSession(paths, names, hosts);
            session.ValidateLoadedIdentities();
            return session;
        }
    }

    public Assembly GetAssembly(string path)
    {
        ValidateLoadedIdentities();
        if (!byPath.TryGetValue(path, out var assembly))
            throw new UnauthorizedAccessException("Assembly is outside the bound signed graph.");
        return assembly;
    }

    // Detects already-present duplicates; cannot make arbitrary host activity atomic.
    public void ValidateLoadedIdentities()
    {
        foreach (var loaded in AppDomain.CurrentDomain.GetAssemblies())
        {
            string name = loaded.GetName().Name!;
            if (byName.TryGetValue(name, out var expected) && !ReferenceEquals(expected, loaded))
                throw new UnauthorizedAccessException("Foreign application identity loaded: " + name);
            if (hosts.TryGetValue(name, out var host) && !ReferenceEquals(host, loaded))
                throw new UnauthorizedAccessException("Foreign host identity loaded: " + name);
        }
    }
}
