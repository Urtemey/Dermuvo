using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Text;

namespace Durevo.Core;

public sealed record NativeArtifactInfo(string Format, string Architecture, string[] RequiredExports);

// Static packaging check only. Never loads or executes the supplied native image.
public static class NativeArtifactInspector
{
    private static readonly string[] Required = ["durevo_run", "durevo_run_strings",
        "durevo_key_create", "durevo_key_destroy", "durevo_run_encrypted", "durevo_run_encrypted_strings"];

    public static NativeArtifactInfo Inspect(string name, byte[] bytes)
    {
        if (bytes.Length < 64 || bytes.Length > 64 * 1024 * 1024) throw new InvalidDataException("Native image size out of bounds.");
        try
        {
            HashSet<string> exports = name switch {
                "durevo_vm.dll" => ReadPe(bytes),
                "libdurevo_vm.so" => ReadElf(bytes),
                _ => throw new InvalidDataException("Unknown native image name.")
            };
            foreach (string required in Required)
                if (!exports.Contains(required)) throw new InvalidDataException("Native backend lacks a defined function export: " + required);
            return new NativeArtifactInfo(name.EndsWith(".dll", StringComparison.Ordinal) ? "PE32+" : "ELF64",
                "x86_64", Required.ToArray());
        }
        catch (Exception e) when (e is BadImageFormatException or OverflowException or ArgumentOutOfRangeException)
        { throw new InvalidDataException("Malformed native image metadata.", e); }
    }

    private static HashSet<string> ReadPe(byte[] bytes)
    {
        using var pe = new PEReader(new MemoryStream(bytes, false));
        var headers = pe.PEHeaders;
        if (headers.PEHeader == null || headers.PEHeader.Magic != PEMagic.PE32Plus ||
            headers.CoffHeader.Machine != Machine.Amd64 ||
            (headers.CoffHeader.Characteristics & Characteristics.Dll) == 0 || headers.CorHeader != null)
            throw new InvalidDataException("Expected a native x86_64 PE DLL.");
        int Rva(uint address, int length, bool executable = false)
        {
            foreach (var section in headers.SectionHeaders)
            {
                long delta = (long)address - section.VirtualAddress;
                if (delta < 0 || delta + length > section.SizeOfRawData) continue;
                if (executable && (section.SectionCharacteristics & SectionCharacteristics.MemExecute) == 0)
                    throw new InvalidDataException("Native function export points outside executable code.");
                int offset = checked(section.PointerToRawData + (int)delta);
                Range(bytes, offset, length); return offset;
            }
            throw new InvalidDataException("Native RVA is outside file-backed sections.");
        }
        var directory = headers.PEHeader.ExportTableDirectory;
        if (directory.RelativeVirtualAddress <= 0 || directory.Size < 40) throw new InvalidDataException("Missing native export directory.");
        int table = Rva((uint)directory.RelativeVirtualAddress, 40);
        uint functions = U32(bytes, table + 20), names = U32(bytes, table + 24);
        if (functions == 0 || functions > 65536 || names == 0 || names > functions) throw new InvalidDataException("Invalid native export counts.");
        int addresses = Rva(U32(bytes, table + 28), checked((int)functions * 4));
        int namePointers = Rva(U32(bytes, table + 32), checked((int)names * 4));
        int ordinals = Rva(U32(bytes, table + 36), checked((int)names * 2));
        var found = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < names; i++)
        {
            int name = Rva(U32(bytes, namePointers + i * 4), 1);
            string symbol = Ascii(bytes, name, Math.Min(bytes.Length, name + 512));
            int ordinal = U16(bytes, ordinals + i * 2);
            if (ordinal >= functions) throw new InvalidDataException("Invalid native export ordinal.");
            uint address = U32(bytes, addresses + ordinal * 4);
            if (!Required.Contains(symbol, StringComparer.Ordinal)) continue;
            if ((ulong)address >= (uint)directory.RelativeVirtualAddress &&
                (ulong)address < (ulong)(uint)directory.RelativeVirtualAddress + (uint)directory.Size)
                throw new InvalidDataException("Forwarded backend exports are not accepted.");
            _ = Rva(address, 1, executable: true);
            if (!found.Add(symbol)) throw new InvalidDataException("Duplicate backend function export.");
        }
        return found;
    }

    private static HashSet<string> ReadElf(byte[] bytes)
    {
        if (bytes[0] != 0x7f || bytes[1] != (byte)'E' || bytes[2] != (byte)'L' || bytes[3] != (byte)'F' ||
            bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 || U16(bytes, 16) != 3 ||
            U16(bytes, 18) != 62 || U32(bytes, 20) != 1 || U16(bytes, 52) != 64)
            throw new InvalidDataException("Expected a little-endian x86_64 ELF shared object.");
        int offset = checked((int)U64(bytes, 40)), count = U16(bytes, 60);
        if (count == 0 || count > 4096 || U16(bytes, 58) != 64) throw new InvalidDataException("Unsupported ELF section table.");
        Range(bytes, offset, checked(count * 64));
        int Section(int index) {
            if (index < 0 || index >= count) throw new InvalidDataException("Invalid ELF section index.");
            return checked(offset + index * 64);
        }
        var found = new HashSet<string>(StringComparer.Ordinal);
        for (int s = 0; s < count; s++)
        {
            int header = Section(s);
            if (U32(bytes, header + 4) != 11) continue; // SHT_DYNSYM only; static symbols are not loader exports.
            int symbols = checked((int)U64(bytes, header + 24)), size = checked((int)U64(bytes, header + 32));
            if (U64(bytes, header + 56) != 24 || size % 24 != 0 || size / 24 > 65536)
                throw new InvalidDataException("Invalid ELF dynamic symbol table.");
            Range(bytes, symbols, size);
            int stringsHeader = Section(checked((int)U32(bytes, header + 40)));
            if (U32(bytes, stringsHeader + 4) != 3) throw new InvalidDataException("Missing ELF symbol string table.");
            int strings = checked((int)U64(bytes, stringsHeader + 24)), stringSize = checked((int)U64(bytes, stringsHeader + 32));
            Range(bytes, strings, stringSize);
            for (int i = 0; i < size / 24; i++)
            {
                int symbol = symbols + i * 24;
                uint index = U32(bytes, symbol);
                if (index >= stringSize) throw new InvalidDataException("Invalid ELF symbol name offset.");
                string name = Ascii(bytes, checked(strings + (int)index), strings + stringSize);
                if (!Required.Contains(name, StringComparer.Ordinal)) continue;
                int binding = bytes[symbol + 4] >> 4, type = bytes[symbol + 4] & 15, visibility = bytes[symbol + 5] & 3;
                int sectionIndex = U16(bytes, symbol + 6);
                if (binding is not (1 or 2) || type != 2 || visibility is not (0 or 3) || sectionIndex == 0)
                    throw new InvalidDataException("Backend export is not a visible, defined ELF function.");
                int code = Section(sectionIndex);
                ulong start = U64(bytes, code + 16), length = U64(bytes, code + 32), value = U64(bytes, symbol + 8);
                if ((U64(bytes, code + 8) & 4) == 0 || value < start || value - start >= length)
                    throw new InvalidDataException("ELF backend export points outside executable code.");
                int codeOffset = checked((int)U64(bytes, code + 24));
                Range(bytes, codeOffset, checked((int)length));
                if (!found.Add(name)) throw new InvalidDataException("Duplicate ELF backend function.");
            }
        }
        return found;
    }

    private static void Range(byte[] bytes, int offset, int length)
    {
        if (offset < 0 || length < 0 || offset > bytes.Length - length) throw new InvalidDataException("Native table is outside file.");
    }
    private static ushort U16(byte[] bytes, int offset) { Range(bytes, offset, 2); return BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2)); }
    private static uint U32(byte[] bytes, int offset) { Range(bytes, offset, 4); return BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4)); }
    private static ulong U64(byte[] bytes, int offset) { Range(bytes, offset, 8); return BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset, 8)); }
    private static string Ascii(byte[] bytes, int offset, int end)
    {
        if (offset < 0 || offset >= end || end > bytes.Length) throw new InvalidDataException("Invalid native symbol string.");
        int limit = Math.Min(end, offset + 512), cursor = offset;
        while (cursor < limit && bytes[cursor] != 0) {
            if (bytes[cursor] > 127) throw new InvalidDataException("Non-ASCII native symbol.");
            cursor++;
        }
        if (cursor == limit) throw new InvalidDataException("Unterminated or oversized native symbol.");
        return Encoding.ASCII.GetString(bytes, offset, cursor - offset);
    }
}
