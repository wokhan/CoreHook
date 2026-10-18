using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.PortableExecutable;


[StructLayout(LayoutKind.Explicit, Pack = 1)]
public unsafe struct OptionalHeader
{
    /// <summary>
    /// The unsigned integer that identifies the state of the image file. The most common number is 0x10B, which identifies it as a normal executable file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable. 
    /// </summary>
    [FieldOffset(0)]
    public readonly PEMagic ImageMagic;

    /// <summary>
    /// The linker major version number.  
    /// </summary>
    [FieldOffset(2)]
    public readonly sbyte MajorLinkerVersion;

    /// <summary>
    /// The linker minor version number. 
    /// </summary>
    [FieldOffset(3)]
    public readonly sbyte MinorLinkerVersion;

    /// <summary>
    /// The size of the code (text) section, or the sum of all code sections if there are multiple sections.
    /// </summary>
    [FieldOffset(4)]
    public readonly uint SizeOfCode;

    /// <summary>
    /// The size of the initialized data section, or the sum of all such sections if there are multiple data sections.
    /// </summary>
    [FieldOffset(8)]
    public readonly uint SizeOfInitializedData;

    /// <summary>
    /// The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.
    /// </summary>
    [FieldOffset(12)]
    public readonly uint SizeOfUninitializedData;

    /// <summary>
    /// The address of the entry point relative to the image base when the executable file is loaded into memory.For program images, this is the starting address.For device drivers, this is the address of the initialization function. An entry point is optional for DLLs.When no entry point is present, this field must be zero.
    /// </summary>
    [FieldOffset(16)]
    public readonly uint AddressOfEntryPoint;

    /// <summary>
    /// The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
    /// </summary>
    [FieldOffset(20)]
    public readonly uint BaseOfCode;

    /// <summary>
    /// PE32 Only: The address that is relative to the image base of the beginning-of-data section when it is loaded into memory. 
    /// </summary>
    [FieldOffset(24)]
    public readonly uint BaseOfData;

    #region Windows specific


    [FieldOffset(28)]
    private readonly uint _imageBase32;

    [FieldOffset(24)]
    private readonly ulong _imageBase64;


    /// <summary>
    /// The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
    /// </summary>
    public readonly ulong ImageBase => ImageMagic == PEMagic.PE32 ? _imageBase32 : _imageBase64;

    /// <summary>
    /// The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
    /// </summary>
    [FieldOffset(32)]
    public readonly uint SectionAlignment;

    /// <summary>
    /// The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture's page size, then FileAlignment must match SectionAlignment.
    /// </summary>
    [FieldOffset(36)]
    public readonly ulong FileAlignment;

    /// <summary>
    /// The major version number of the required operating system.
    /// </summary>
    [FieldOffset(40)]
    public readonly ushort MajorOperatingSystemVersion;

    /// <summary>
    /// The minor version number of the required operating system.
    /// </summary>
    [FieldOffset(42)]
    public readonly ushort MinorOperatingSystemVersion;

    /// <summary>
    /// The major version number of the image.
    /// </summary>
    [FieldOffset(44)]
    public readonly ushort MajorImageVersion;

    /// <summary>
    /// The minor version number of the image.
    /// </summary>
    [FieldOffset(46)]
    public readonly ushort MinorImageVersion;

    /// <summary>
    /// The major version number of the subsystem.
    /// </summary>
    [FieldOffset(48)]
    public readonly ushort MajorSubsystemVersion;

    /// <summary>
    /// PE32: The minor version number of the subsystem.
    /// </summary>
    [FieldOffset(50)]
    public readonly ushort MinorSubsystemVersion;

    /// <summary>
    /// Reserved, must be zero.
    /// </summary>
    [FieldOffset(52)]
    public readonly ulong Win32VersionValue;

    /// <summary>
    /// The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.
    /// </summary>
    [FieldOffset(56)]
    public readonly uint SizeOfImage;

    /// <summary>
    /// The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
    /// </summary>
    [FieldOffset(60)]
    public readonly uint SizeOfHeaders;

    /// <summary>
    /// The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.
    /// </summary>
    [FieldOffset(64)]
    public readonly ulong CheckSum;

    /// <summary>
    /// The subsystem that is required to run this image. For more information, see Windows Subsystem.
    /// </summary>
    [FieldOffset(68)]
    public readonly Subsystem Subsystem;

    /// <summary>
    /// For more information, see DLL Characteristics later in this specification.
    /// </summary>
    [FieldOffset(70)]
    public readonly DllCharacteristics DllCharacteristics;

    /// <summary>
    /// The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached.
    /// </summary>
    [FieldOffset(72)]
    public readonly uint SizeOfStackReserve;

    [FieldOffset(76)]
    private readonly uint _sizeOfStackCommit32;

    [FieldOffset(80)]
    private readonly ulong _sizeOfStackCommit64;

    /// <summary>
    /// The size of the stack to commit.
    /// </summary>
    public readonly ulong SizeOfStackCommit => ImageMagic == PEMagic.PE32 ? _sizeOfStackCommit32 : _sizeOfStackCommit64;

    [FieldOffset(80)]
    private readonly uint _sizeOfHeapReserve32;

    [FieldOffset(88)]
    private readonly ulong _sizeOfHeapReserve64;

    /// <summary>
    /// The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached.
    /// </summary>
    public readonly ulong SizeOfHeapReserve => ImageMagic == PEMagic.PE32 ? _sizeOfHeapCommit32 : _sizeOfHeapCommit64;

    [FieldOffset(84)]
    private readonly uint _sizeOfHeapCommit32;

    [FieldOffset(96)]
    private readonly ulong _sizeOfHeapCommit64;

    /// <summary>
    /// The size of the local heap space to commit.
    /// </summary>
    public readonly ulong SizeOfHeapCommit => ImageMagic == PEMagic.PE32 ? _sizeOfHeapCommit32 : _sizeOfHeapCommit64;

    [FieldOffset(88)]
    private readonly uint LoaderFlags32;

    [FieldOffset(104)]
    private readonly uint LoaderFlags64;

    /// <summary>
    /// Reserved, must be zero.
    /// </summary>
    public readonly uint LoaderFlags => ImageMagic == PEMagic.PE32 ? LoaderFlags32 : LoaderFlags64;

    [FieldOffset(92)]
    private readonly uint NumberOfRvaAndSizes32;

    [FieldOffset(108)]
    private readonly uint NumberOfRvaAndSizes64;

    /// <summary>
    /// PE32: The number of data-directory entries in the remainder of the optional header. Each describes a location and size.
    /// </summary>
    public readonly uint NumberOfRvaAndSizes => ImageMagic == PEMagic.PE32 ? NumberOfRvaAndSizes32 : NumberOfRvaAndSizes64;

    #endregion

    [FieldOffset(96)]
    //private fixed byte DataDirectory32[16 * 8];
    private byte DataDirectory32;

    [FieldOffset(112)]
    private byte DataDirectory64;



    public unsafe readonly DataDirectory DataDirectory(ImageDirectoryEntry imageDirectoryEntry)
    {
        if (ImageMagic == PEMagic.PE32)
        {
            if ((uint)imageDirectoryEntry >= NumberOfRvaAndSizes32)
            {
                return new();
            }

            fixed (byte* directories = &DataDirectory32)
            {
                return ((DataDirectory*)directories)[(ushort)imageDirectoryEntry];
            }
        }
        else
        {
            if ((uint)imageDirectoryEntry >= NumberOfRvaAndSizes64)
            {
                return new();
            }

            fixed (byte* directories = &DataDirectory64)
            {
                return ((DataDirectory*)directories)[(ushort)imageDirectoryEntry];
            }
        }
    }

    public T ResolveDirectory<T>(PEReader reader, ImageDirectoryEntry imageDirectoryEntry) where T : new()
    {
        return reader.Read<T>((nint)DataDirectory(imageDirectoryEntry).VirtualAddress);
    }
}
