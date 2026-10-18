using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.PortableExecutable;

[StructLayout(LayoutKind.Sequential)]
public unsafe struct DosHeader
{
    public readonly ushort e_magic;
    public readonly ushort e_cblp;
    public readonly ushort e_cp;
    public readonly ushort e_crlc;
    public readonly ushort e_cparhdr;
    public readonly ushort e_minalloc;
    public readonly ushort e_maxalloc;
    public readonly ushort e_ss;
    public readonly ushort e_sp;
    public readonly ushort e_csum;
    public readonly ushort e_ip;
    public readonly ushort e_cs;
    public readonly ushort e_lfarlc;
    public readonly ushort e_ovno;
    public fixed ushort e_res1[4];
    public readonly ushort e_oemid;
    public readonly ushort e_oeminfo;
    public fixed ushort e_res2[10];
    public readonly uint e_lfanew;
}
