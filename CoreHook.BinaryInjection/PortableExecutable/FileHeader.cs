using System;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.PortableExecutable;

[StructLayout(LayoutKind.Sequential)]
public readonly struct FileHeader
{
    /// <summary>
    /// The number that identifies the type of target machine. 
    /// </summary>
    public readonly Machine Machine;

    /// <summary>
    /// The number of sections. This indicates the size of the section table, which immediately follows the headers. 
    /// </summary>
    public readonly ushort NumberOfSections;

    private readonly uint _timeDateStamp;

    /// <summary>
    /// The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), which indicates when the file was created. 
    /// </summary>
    public readonly DateTime TimeDateStamp => DateTime.FromFileTime(_timeDateStamp);

    /// <summary>
    /// The file offset of the COFF symbol table, or zero if no COFF symbol table is present. This value should be zero for an image because COFF debugging information is deprecated. 
    /// </summary>
    public readonly uint PointerToSymbolTable;

    /// <summary>
    /// The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. This value should be zero for an image because COFF debugging information is deprecated. 
    /// </summary>
    public readonly uint NumberOfSymbols;

    /// <summary>
    /// The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file. For a description of the header format, see <see cref="OptionalHeader"/> (Image Only). 
    /// </summary>
    public readonly ushort SizeOfOptionalHeader;

    /// <summary>
    /// The flags that indicate the attributes of the file.
    /// </summary>
    public readonly Characteristics Characteristics;
}
