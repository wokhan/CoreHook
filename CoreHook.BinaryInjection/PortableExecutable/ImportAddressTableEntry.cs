using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.PortableExecutable;

[StructLayout(LayoutKind.Explicit, Pack = 1)]
public class ImportAddressTableEntry
{
    [FieldOffset(0)]
    public readonly uint SymbolAddress32;

    [FieldOffset(0)]
    public readonly ulong SymbolAddress64;
}
