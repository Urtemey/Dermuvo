using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Text;
using Durevo.Core;

internal static class NativeArtifactSuite
{
    internal static int Run()
    {
        string name = OperatingSystem.IsWindows() ? "durevo_vm.dll" : "libdurevo_vm.so";
        byte[] original = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, name));
        var result = NativeArtifactInspector.Inspect(name, original);
        int checks = 1;
        if (result.Architecture != "x86_64" || result.RequiredExports.Length != 6) throw new Exception("Native inspection mismatch.");
        void Reject(byte[] bytes, string? filename = null)
        {
            try { NativeArtifactInspector.Inspect(filename ?? name, bytes); }
            catch (InvalidDataException) { checks++; return; }
            throw new Exception("Invalid native image was accepted.");
        }
        Reject([]); Reject(new byte[64]); Reject(original[..64]); Reject(original, "unexpected.bin");
        Reject(original, name.EndsWith(".dll") ? "libdurevo_vm.so" : "durevo_vm.dll");
        byte[] missing = original.ToArray();
        int symbolName = missing.AsSpan().IndexOf(Encoding.ASCII.GetBytes("durevo_run_encrypted_strings\0"));
        if (symbolName < 0) throw new Exception("Required test export not found.");
        missing[symbolName] = (byte)'x'; Reject(missing);
        byte[] wrongArchitecture = original.ToArray();
        if (OperatingSystem.IsWindows())
        {
            int pe = BitConverter.ToInt32(original, 0x3c);
            BinaryPrimitives.WriteUInt16LittleEndian(wrongArchitecture.AsSpan(pe + 4, 2), 0xaa64);
            Reject(wrongArchitecture);
            byte[] badOffset = original.ToArray();
            BinaryPrimitives.WriteInt32LittleEndian(badOffset.AsSpan(0x3c, 4), int.MaxValue);
            Reject(badOffset);
            using var image = new PEReader(new MemoryStream(original));
            int Rva(int rva) {
                var section = image.PEHeaders.SectionHeaders.Single(s => rva >= s.VirtualAddress && rva < s.VirtualAddress + s.SizeOfRawData);
                return section.PointerToRawData + rva - section.VirtualAddress;
            }
            int directoryRva = image.PEHeaders.PEHeader!.ExportTableDirectory.RelativeVirtualAddress;
            int directory = Rva(directoryRva);
            int addresses = Rva(BitConverter.ToInt32(original, directory + 28));
            byte[] forwarded = original.ToArray();
            BinaryPrimitives.WriteInt32LittleEndian(forwarded.AsSpan(addresses, 4), directoryRva);
            Reject(forwarded);
        }
        else
        {
            BinaryPrimitives.WriteUInt16LittleEndian(wrongArchitecture.AsSpan(18, 2), 183); Reject(wrongArchitecture);
            byte[] wrongClass = original.ToArray(); wrongClass[4] = 1; Reject(wrongClass);
            byte[] wrongEndian = original.ToArray(); wrongEndian[5] = 2; Reject(wrongEndian);
            byte[] badOffset = original.ToArray();
            BinaryPrimitives.WriteUInt64LittleEndian(badOffset.AsSpan(40, 8), ulong.MaxValue); Reject(badOffset);
            int sections = checked((int)BitConverter.ToUInt64(original, 40));
            int count = BitConverter.ToUInt16(original, 60);
            bool changed = false;
            for (int i = 0; i < count; i++)
            {
                int header = sections + i * 64;
                if (BitConverter.ToUInt32(original, header + 4) != 11) continue;
                int symbols = checked((int)BitConverter.ToUInt64(original, header + 24));
                int size = checked((int)BitConverter.ToUInt64(original, header + 32));
                int stringsHeader = sections + checked((int)BitConverter.ToUInt32(original, header + 40)) * 64;
                int strings = checked((int)BitConverter.ToUInt64(original, stringsHeader + 24));
                for (int n = 0; n < size / 24; n++)
                {
                    int symbol = symbols + n * 24;
                    if (strings + BitConverter.ToUInt32(original, symbol) != symbolName) continue;
                    byte[] undefined = original.ToArray();
                    undefined[symbol + 6] = 0; undefined[symbol + 7] = 0; Reject(undefined);
                    byte[] local = original.ToArray(); local[symbol + 4] = 2; Reject(local);
                    byte[] hidden = original.ToArray(); hidden[symbol + 5] = 2; Reject(hidden);
                    changed = true;
                }
            }
            if (!changed) throw new Exception("Did not exercise ELF export mutations.");
        }
        // Mutation stability is not an assertion that all changed executable bytes must be rejected.
        var random = new Random(38923);
        for (int i = 0; i < 2000; i++)
        {
            byte[] data = i % 2 == 0 ? new byte[random.Next(64, 4096)] : original.ToArray();
            if (i % 2 == 0) random.NextBytes(data);
            else for (int j = 0; j < 8; j++) data[random.Next(data.Length)] ^= (byte)random.Next(1, 256);
            try { NativeArtifactInspector.Inspect(name, data); }
            catch (InvalidDataException) { }
            checks++;
        }
        Console.WriteLine($"Native artifact inspection: {checks} format/export/rejection and parser-stability checks.");
        return checks;
    }
}
