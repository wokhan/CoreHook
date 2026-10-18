using CoreHook.BinaryInjection.PortableExecutable;

using DNNE;

using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.Tests;

public class PEImageTest
{
    [UnmanagedCallersOnly]
    public static int DummyExport(int prm1) => 1;

    [UnmanagedCallersOnly]
    public static int DummyExportOther(int prm1, int prm2) => 1;

    [DllImport("CoreHook.BinaryInjection.TestsNE.dll", EntryPoint = nameof(DummyExport))]
    public static extern int DummyImport1(int prm1);

    [Fact]
    public void ShouldParseImageWhenUsingReadMemory()
    {
        var process = Process.GetCurrentProcess();

        // Force import the corresponding DLL (could properly load the module directly but well...
        DummyImport1(0);

        var modules = process.Modules.Cast<ProcessModule>().Select(mod => mod.ModuleName);
        var selfmodule = process.Modules.Cast<ProcessModule>().First(mod => mod.ModuleName == "CoreHook.BinaryInjection.TestsNE.dll");
        var image = PEImage.CreateForProcessModule(process.SafeHandle, selfmodule.BaseAddress);

        var exportedFunctions = image.Exports;
        var importedFunctions = image.Imports;
    }

    [Fact]
    public void ShouldParseImageWhenUsingDirectMemoryAccess()
    {
        var process = Process.GetCurrentProcess();

        DummyImport1(0);

        var selfmodule = process.Modules.Cast<ProcessModule>().First(mod => mod.ModuleName == "CoreHook.BinaryInjection.TestsNE.dll");
        var image = PEImage.CreateForProcessModule(selfmodule.BaseAddress);

        var exportedFunctions = image.Exports;
        var importedFunctions = image.Imports;
    }
}
