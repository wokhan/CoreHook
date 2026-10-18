using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.PortableExecutable;

[StructLayout(LayoutKind.Explicit, Pack = 1)]
public unsafe readonly struct ImportLookupTable
{
    [FieldOffset(0)]
    public readonly ushort OrdinalNumber;

    [FieldOffset(0)]
    private readonly uint _hintNameTableRVA;

    // The Name address is stored on 31bits only: get rid of the last one by shifting right once
    public nint HintNameTableRVA => (nint)(_hintNameTableRVA >> 1);

    [FieldOffset(31)]
    public readonly bool ImportByOrdinal32;

    [FieldOffset(63)]
    public readonly bool ImportByOrdinal64;
}
