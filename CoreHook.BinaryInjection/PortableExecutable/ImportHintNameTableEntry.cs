using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.PortableExecutable;

[StructLayout(LayoutKind.Sequential)]
public readonly struct ImportHintNameTableEntry
{
    public readonly ushort Hint;
    public readonly byte Name;
}
