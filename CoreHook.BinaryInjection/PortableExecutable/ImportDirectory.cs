using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.PortableExecutable;

[StructLayout(LayoutKind.Sequential)]
public readonly struct ImportDirectory
{
    /// <summary>
    /// The RVA of the import lookup table. This table contains a name or ordinal for each import. (The name "Characteristics" is used in Winnt.h, but no longer describes this field.) 
    /// </summary>
    public readonly uint ImportLookupTableRVA;

    private readonly uint _timeDateStamp;

    /// <summary>
    /// The stamp that is set to zero until the image is bound. After the image is bound, this field is set to the time/data stamp of the DLL. 
    /// </summary>
    public readonly DateTime TimeDateStamp => DateTime.FromFileTime(_timeDateStamp);

    /// <summary>
    /// The index of the first forwarder reference. 
    /// </summary>
    public readonly uint ForwarderChain;

    /// <summary>
    /// The address of an ASCII string that contains the name of the DLL. This address is relative to the image base. 
    /// </summary>
    public readonly uint NameRVA;

    /// <summary>
    /// The RVA of the import address table. The contents of this table are identical to the contents of the import lookup table until the image is bound. 
    /// </summary>
    public readonly uint ImportAddressTableRVA;

    public unsafe readonly IEnumerable<(string DllName, string MethodName, nint Address)> GetImportedFunctions(PEReader reader, nint moduleBaseAddress, bool is64bits)
    {
        List<(string DllName, string MethodName, nint Address)> imports = new();
        var dllName = reader.ReadStringANSI((nint)NameRVA);
        var addressEntry = reader.ReadArray<ImportAddressTableEntry>((nint)ImportAddressTableRVA, entry => entry.SymbolAddress32 == 0);

        var entries = reader.ReadArray<ImportLookupTable>((nint)ImportAddressTableRVA, entry => entry.OrdinalNumber == 0);
        for (var i = 0; i < entries.Length; i++)
        {
            var entry = entries[i];
            var importByOrdinal = is64bits ? entry.ImportByOrdinal64 : entry.ImportByOrdinal32;
            var hintNameEntry = reader.Read<ImportHintNameTableEntry>(entry.HintNameTableRVA);
            var address = is64bits ? addressEntry[i].SymbolAddress64 : addressEntry[i].SymbolAddress32;
            string methodName = importByOrdinal ? reader.ReadStringANSI((nint)(&hintNameEntry.Name)) : hintNameEntry.Hint.ToString();

            imports.Add((dllName, methodName, (nint)address));
        }
        
        return imports;
    }
}
