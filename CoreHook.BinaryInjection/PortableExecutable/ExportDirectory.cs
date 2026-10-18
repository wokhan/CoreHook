using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.PortableExecutable;

[StructLayout(LayoutKind.Sequential)]
public readonly struct ExportDirectory
{
    public readonly uint ExportFlags;
    public readonly uint TimeDateStamp;
    public readonly ushort MajorVersion;
    public readonly ushort MinorVersion;
    public readonly uint NameRVA;
    public readonly uint OrdinalBase;
    public readonly uint AddressTableEntries;
    public readonly uint NumberOfNamesPointers;
    public readonly uint ExportAddressTableRVA;
    public readonly uint NamePointerRVA;
    public readonly uint OrdinalTableRVA;

    internal unsafe readonly IList<(string DllName, string MethodName, nint Address)> GetExportedFunctions(PEReader reader, nint moduleBaseAddress)
    {
        var dllName = reader.ReadStringANSI((nint)NameRVA);

        var namesPointers = reader.ReadArray<uint>((nint)NamePointerRVA, NumberOfNamesPointers);
        var ordinals = reader.ReadArray<ushort>((nint)OrdinalTableRVA, NumberOfNamesPointers);
        var addresses = reader.ReadArray<uint>((nint)ExportAddressTableRVA, AddressTableEntries);

        var localOrdinalBase = OrdinalBase;

        //TODO: check if +1 is necessary
        return namesPointers.Zip(ordinals.Select(ordinal => addresses[ordinal - localOrdinalBase + 1]), (nameAddress, functionAddress) => (dllName, reader.ReadStringANSI((nint)nameAddress), moduleBaseAddress + (nint)functionAddress))
                            .ToList();
    }
}
