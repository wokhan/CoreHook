using System.Collections.Generic;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.PortableExecutable;

public class PEImage
{
    private readonly PEReader reader;

    private readonly nint moduleBaseAddress;

    public DosHeader dosHeaders;
    public NtHeaders ntHeaders;

    public IList<(string DllName, string MethodName, nint Address)> Exports;
    public IList<(string DllName, string MethodName, nint Address)> Imports;

    private bool is64bits;

    private PEImage(SafeHandle? processHandle, nint moduleBaseAddress)
    {
        this.moduleBaseAddress = moduleBaseAddress;

        reader = new PEReader(processHandle, moduleBaseAddress);

        Init();
    }
    public static PEImage CreateForProcessModule(nint moduleBaseAddress)
    {
        return new PEImage(null, moduleBaseAddress);
    }

    public static PEImage CreateForProcessModule(SafeHandle? processHandle, nint moduleBaseAddress)
    {
        return new PEImage(processHandle, moduleBaseAddress);
    }

    private unsafe void Init()
    {
        // TODO: Trying to use the Unsafe API, but it might cause some issues if alignment is not the same depending on the platform since no marshalling occurs here. I've to double check that.
        dosHeaders = reader.Read<DosHeader>(0);

        ntHeaders = reader.Read<NtHeaders>((nint)dosHeaders.e_lfanew);

        is64bits = ntHeaders.OptionalHeader.ImageMagic == PEMagic.PE32Plus;

        var exportDirectory = ntHeaders.OptionalHeader.ResolveDirectory<ExportDirectory>(reader, ImageDirectoryEntry.ImageDirectoryEntryExport);
        //var importDirectory = ntHeaders.OptionalHeader.ResolveDirectory<ImportDirectory>(reader, ImageDirectoryEntry.ImageDirectoryEntryImport);

        Exports = exportDirectory.GetExportedFunctions(reader, moduleBaseAddress);

        var importDirectoryRVA = ntHeaders.OptionalHeader.DataDirectory(ImageDirectoryEntry.ImageDirectoryEntryImport).VirtualAddress;
        var importDirectory = reader.ReadArray<ImportDirectory>((nint)importDirectoryRVA, dir => dir.NameRVA == 0);

        Imports = importDirectory.SelectMany(dir => dir.GetImportedFunctions(reader, moduleBaseAddress, is64bits)).ToList();
    }
}
