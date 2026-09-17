using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Mono.Cecil;

namespace Durevo.Runtime;

/// <summary>
/// Captures signed application images and validates their complete static reference graph.
/// This is preflight validation, not exclusive runtime binding or a sandbox.
/// </summary>
public sealed class VerifiedManagedGraph
{
    private readonly Dictionary<string, VerifiedManagedImage> images;
    internal IReadOnlyDictionary<string, string> ApplicationIdentities { get; }
    internal IReadOnlyDictionary<string, string> HostIdentities { get; }
    public string Product { get; }
    public ulong Revision { get; }
    public IReadOnlyList<string> Paths { get; }

    private VerifiedManagedGraph(VerifiedRelease release, Dictionary<string, VerifiedManagedImage> images, Dictionary<string, string> identities, Dictionary<string, string> hosts)
    {
        Product = release.Product;
        Revision = release.Revision;
        this.images = images;
        ApplicationIdentities = identities; HostIdentities = hosts;
        Paths = Array.AsReadOnly(images.Keys.OrderBy(p => p, StringComparer.Ordinal).ToArray());
    }

    // No path reopening, but dependency binding still belongs to the host. The name is
    // deliberately explicit: Capture is NOT sufficient to turn Assembly.Load into a sandbox.
    public Assembly LoadImageUsingHostResolution(string path)
    {
        if (!images.TryGetValue(path, out var image))
            throw new UnauthorizedAccessException("Image was not captured in this graph.");
        return image.Load();
    }

    public VerifiedMonoSession BindMono(IReadOnlyCollection<Assembly> trustedHosts) => VerifiedMonoSession.Bind(this, trustedHosts);

    public static VerifiedManagedGraph Capture(VerifiedRelease release, string root,
        IReadOnlyCollection<string> applicationPaths, IReadOnlyCollection<AssemblyName> trustedHostIdentities,
        int maximumTotalBytes = 128 * 1024 * 1024)
    {
        if (release is null || applicationPaths is null || trustedHostIdentities is null)
            throw new ArgumentNullException();
        if (applicationPaths.Count == 0 || applicationPaths.Count > 128 ||
            trustedHostIdentities.Count > 512 || maximumTotalBytes < 1 || maximumTotalBytes > 128 * 1024 * 1024)
            throw new ArgumentOutOfRangeException("Graph limits exceeded.");
        var host = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var supplied in trustedHostIdentities)
        {
            if (supplied is null) throw new ArgumentException("Null host identity.");
            var identity = new AssemblyName(supplied.FullName); // Snapshot mutable caller metadata.
            if (string.IsNullOrWhiteSpace(identity.Name) || identity.Version is null ||
                !host.TryAdd(identity.Name, identity.FullName))
                throw new ArgumentException("Invalid or duplicate host identity.");
        }
        var images = new Dictionary<string, VerifiedManagedImage>(StringComparer.Ordinal);
        var identities = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var references = new List<string>();
        long total = 0;
        foreach (string path in applicationPaths)
        {
            if (images.ContainsKey(path)) throw new ArgumentException("Duplicate application path.");
            var entry = release.Files.SingleOrDefault(f => f.Path == path)
                ?? throw new UnauthorizedAccessException("Application image is not signed.");
            total = checked(total + entry.Length);
            if (total > maximumTotalBytes) throw new InvalidDataException("Graph byte budget exceeded.");
            var image = VerifiedManagedImage.Capture(release, root, path,
                Math.Min(maximumTotalBytes, 64 * 1024 * 1024));
            using var stream = image.OpenMetadata();
            // Deferred reading avoids resolving attribute types from the external filesystem.
            using var module = ModuleDefinition.ReadModule(stream, new ReaderParameters {
                ReadingMode = ReadingMode.Deferred, AssemblyResolver = RejectingResolver.Instance
            });
            if (module.Assembly is null || module.Assembly.Modules.Count != 1 ||
                (module.Attributes & ModuleAttributes.ILOnly) == 0 || module.ModuleReferences.Count != 0)
                throw new NotSupportedException("Only single-module managed images without native imports are supported.");
            if (module.Types.Any(t => t.Name == "<Module>" && t.Methods.Any(m => m.Name == ".cctor")))
                throw new NotSupportedException("Module initializers cannot execute during graph binding.");
            if (module.AssemblyReferences.Count > 512)
                throw new InvalidDataException("Too many assembly references.");
            string name = module.Assembly.Name.Name;
            string fullName = new AssemblyName(module.Assembly.Name.FullName).FullName;
            if (host.ContainsKey(name) || !identities.TryAdd(name, fullName))
                throw new InvalidDataException("Application/host assembly identity collision.");
            foreach (var reference in module.AssemblyReferences)
                references.Add(new AssemblyName(reference.FullName).FullName);
            images.Add(path, image);
        }
        foreach (string reference in references)
        {
            string name = new AssemblyName(reference).Name!;
            string? expected;
            if (!identities.TryGetValue(name, out expected) && !host.TryGetValue(name, out expected))
                throw new UnauthorizedAccessException("Unsigned or untrusted static dependency: " + reference);
            if (!string.Equals(expected, reference, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Dependency identity/version mismatch: " + reference);
        }
        return new VerifiedManagedGraph(release, images, identities, host);
    }

    private sealed class RejectingResolver : IAssemblyResolver
    {
        internal static readonly RejectingResolver Instance = new RejectingResolver();
        public AssemblyDefinition Resolve(AssemblyNameReference name) =>
            throw new NotSupportedException("Preflight must not resolve external code.");
        public AssemblyDefinition Resolve(AssemblyNameReference name, ReaderParameters parameters) => Resolve(name);
        public void Dispose() { }
    }
}
