using System;
using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.PortableExecutable;

[StructLayout(LayoutKind.Sequential)]
public unsafe struct NtHeaders
{
    private fixed sbyte _signature[4]; // Always PE\0\0 for a Windows image

    public string Signature => new(new char[] { (char)_signature[0], (char)_signature[1], (char)_signature[2], (char)_signature[3] });

    public readonly FileHeader FileHeader;

    public readonly OptionalHeader OptionalHeader;
}
