using System.Collections.Immutable;
using System.Runtime.InteropServices;

namespace PEscan;

/// <summary>
/// Парсер PE-файлов для извлечения списка импортируемых DLL
/// </summary>
public static class PeParser
{
    private const ushort ImageDosSignature = 0x5A4D; // "MZ"
    private const uint ImageNtSignature = 0x00004550; // "PE\0\0"

    private const int ImageDirectoryEntryImport = 1;

    public static PeFileInfo Parse(string path)
    {
        using var fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var br = new BinaryReader(fs);

        if (fs.Length < 0x100)
            throw new InvalidDataException("File too small to be a valid PE file.");

        fs.Position = 0;
        var dosMagic = br.ReadUInt16();
        if (dosMagic != ImageDosSignature)
            throw new InvalidDataException("Invalid DOS signature (not an MZ / PE file).");

        fs.Position = 0x3C;
        var e_lfanew = br.ReadUInt32();

        if (e_lfanew + 0x18 > fs.Length)
            throw new InvalidDataException("Invalid e_lfanew offset.");

        fs.Position = e_lfanew;
        var ntSignature = br.ReadUInt32();
        if (ntSignature != ImageNtSignature)
            throw new InvalidDataException("Invalid NT signature.");

        var machine = br.ReadUInt16();
        var numberOfSections = br.ReadUInt16();
        fs.Position += 12;
        var sizeOfOptionalHeader = br.ReadUInt16();
        fs.Position += 2;

        long optionalHeaderStart = fs.Position;
        var magic = br.ReadUInt16();
        bool is64 = magic == 0x20b; // PE64 (32+)
        bool is32 = magic == 0x10b; // PE32
        if (!is32 && !is64)
            throw new InvalidDataException("Unsupported PE optional header magic.");

        if (sizeOfOptionalHeader < (is64 ? 0x70 : 0x60) + 8)
            throw new InvalidDataException("Optional header too small.");
        
        fs.Position = optionalHeaderStart + (is64 ? 0x70 : 0x60);

        // DataDirectory - массив из 16 записей по 8 байт (RVA + Size)
        // Индекс 0 = Export Table, Индекс 1 = Import Table
        // Пропускаем Export Table (8 байт) и читаем Import Table
        br.ReadUInt32(); // Export Table RVA
        br.ReadUInt32(); // Export Table Size
        
        var importDirectoryRva = br.ReadUInt32(); // VirtualAddress
        var importDirectorySize = br.ReadUInt32(); // Size

        fs.Position = optionalHeaderStart + sizeOfOptionalHeader;

        var sections = new List<ImageSectionHeader>();
        for (int i = 0; i < numberOfSections; i++)
        {
            var section = new ImageSectionHeader
            {
                Name = br.ReadBytes(8),
                VirtualSize = br.ReadUInt32(),
                VirtualAddress = br.ReadUInt32(),
                SizeOfRawData = br.ReadUInt32(),
                PointerToRawData = br.ReadUInt32(),
                PointerToRelocations = br.ReadUInt32(),
                PointerToLinenumbers = br.ReadUInt32(),
                NumberOfRelocations = br.ReadUInt16(),
                NumberOfLinenumbers = br.ReadUInt16(),
                Characteristics = br.ReadUInt32()
            };
            sections.Add(section);
        }

        uint RvaToFileOffset(uint rva)
        {
            if (rva == 0)
                return 0;

            foreach (var s in sections)
            {
                uint sectionSize = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + sectionSize)
                {
                    if (s.PointerToRawData == 0)
                        continue;

                    uint offset = s.PointerToRawData + (rva - s.VirtualAddress);
                    if (offset < fs.Length)
                        return offset;
                }
            }

            return 0;
        }

        var importedDlls = ImmutableHashSet.CreateBuilder<string>(StringComparer.OrdinalIgnoreCase);

        if (importDirectoryRva != 0 && importDirectorySize > 0)
        {
            var importTableOffset = RvaToFileOffset(importDirectoryRva);
            if (importTableOffset == 0 || importTableOffset >= fs.Length)
            {
                return new PeFileInfo(path, is64, importedDlls.ToImmutableArray());
            }

            fs.Position = importTableOffset;
            long importTableEnd = Math.Min(importTableOffset + importDirectorySize, fs.Length - 20);

            while (fs.Position <= importTableEnd)
            {
                long descriptorPosition = fs.Position;

                if (descriptorPosition + 20 > fs.Length)
                    break;

                var originalFirstThunk = br.ReadUInt32();
                var timeDateStamp = br.ReadUInt32();
                var forwarderChain = br.ReadUInt32();
                var nameRva = br.ReadUInt32();
                var firstThunk = br.ReadUInt32();

                if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                    break;

                if (nameRva == 0)
                {
                    fs.Position = descriptorPosition + 20;
                    continue;
                }

                var nameOffset = RvaToFileOffset(nameRva);
                if (nameOffset == 0 || nameOffset >= fs.Length)
                {
                    fs.Position = descriptorPosition + 20;
                    continue;
                }

                try
                {
                    long savedPosition = fs.Position;
                    fs.Position = nameOffset;
                    
                    if (nameOffset < fs.Length)
                    {
                        var dllName = ReadAsciiString(br, fs.Length);
                        if (!string.IsNullOrWhiteSpace(dllName))
                        {
                            importedDlls.Add(dllName.Trim());
                        }
                    }
                    
                    fs.Position = savedPosition;
                }
                catch
                {
                    // ошибки чтения dll name
                }

                fs.Position = descriptorPosition + 20;
            }
        }

        return new PeFileInfo(path, is64, importedDlls.ToImmutableArray());
    }

    private static string ReadAsciiString(BinaryReader br, long maxLength)
    {
        var bytes = new List<byte>();
        long startPos = br.BaseStream.Position;
        
        while (br.BaseStream.Position < maxLength)
        {
            byte b = br.ReadByte();
            if (b == 0)
                break;
            bytes.Add(b);
            
            // защита от бесконечного цикла (TODO: мб поменяю)
            if (bytes.Count > 260)
                break;
        }
        
        return bytes.Count > 0 
            ? System.Text.Encoding.ASCII.GetString(CollectionsMarshal.AsSpan(bytes))
            : string.Empty;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct ImageSectionHeader
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;

        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }
}


