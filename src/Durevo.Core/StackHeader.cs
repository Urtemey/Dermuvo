using System.Reflection.PortableExecutable;
using Mono.Cecil;

namespace Durevo.Core;

// Cecil's linear max-stack inference can underestimate backward edges carrying values
// after block permutation. The original valid body is an upper bound; each rewrite
// adds at most two stack slots. Preserve that bound in the emitted fat method header.
internal static class StackHeader
{
    internal static void PreserveBounds(string path, IReadOnlyDictionary<string, int> bounds)
    {
        var patches = new List<(long Offset, ushort Bound)>();
        using (var module = ModuleDefinition.ReadModule(path))
        using (var stream = File.OpenRead(path))
        using (var pe = new PEReader(stream))
        {
            foreach (var method in Protector.Methods(module).Where(m => bounds.ContainsKey(Protector.MethodIdentity(m))))
            {
                int bound = bounds[Protector.MethodIdentity(method)];
                if (bound < 0 || bound > ushort.MaxValue) throw new InvalidDataException("Invalid stack bound.");
                var section = pe.PEHeaders.SectionHeaders.Single(s =>
                    method.RVA >= s.VirtualAddress && method.RVA < (long)s.VirtualAddress + s.SizeOfRawData);
                long offset = (long)section.PointerToRawData + method.RVA - section.VirtualAddress;
                stream.Position = offset;
                int flags = stream.ReadByte();
                if ((flags & 3) == 2)
                {
                    if (bound > 8) throw new InvalidDataException("Tiny body cannot carry the required stack bound.");
                }
                else if ((flags & 3) == 3) patches.Add((offset + 2, (ushort)Math.Max(bound, method.Body.MaxStackSize)));
                else throw new InvalidDataException("Unknown method header.");
            }
        }
        using var output = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None);
        using var writer = new BinaryWriter(output);
        foreach (var patch in patches)
        {
            output.Position = patch.Offset; writer.Write(patch.Bound);
        }
    }
}
