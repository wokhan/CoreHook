using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.PortableExecutable;

[StructLayout(LayoutKind.Sequential)]
public unsafe readonly struct DataDirectory
{
    public readonly uint VirtualAddress;
    public readonly uint Size;
}
