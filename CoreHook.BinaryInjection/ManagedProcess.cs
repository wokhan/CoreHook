﻿using CoreHook.BinaryInjection.PortableExecutable;

using Microsoft.Win32.SafeHandles;

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;

using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using Windows.Win32.Foundation;
using Windows.Win32.System.ProcessStatus;
using Windows.Win32.System.Threading;

namespace CoreHook.BinaryInjection.RemoteInjection;

public sealed partial class ManagedProcess : IDisposable
{
    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial SafeWaitHandle CreateRemoteThread(SafeHandle processHandle, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    private readonly Memory.MemoryManager _memoryManager;
    private int targetProcessId;

    public Process Process { get; }

    public SafeFileHandle SafeHandle { get; }

    private const int DefaultProcessAccess = (int)(
            PROCESS_ACCESS_RIGHTS.PROCESS_CREATE_THREAD |
            PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_INFORMATION |
            PROCESS_ACCESS_RIGHTS.PROCESS_VM_OPERATION |
            PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ |
            PROCESS_ACCESS_RIGHTS.PROCESS_VM_WRITE);

    public ManagedProcess(Process process, int access = DefaultProcessAccess)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            throw new PlatformNotSupportedException("Assembly module loading is not supported on this platform.");
        }

        Process = process;
        SafeHandle = GetProcessHandle((uint)process.Id, access);

        _memoryManager = new Memory.MemoryManager(this.SafeHandle);
    }

    public ManagedProcess(int targetProcessId, int access = DefaultProcessAccess) : this(Process.GetProcessById(targetProcessId), access)
    {
        if (Process is null)
        {
            throw new ArgumentException($"Unable to create a ManagedProcess object for pid {targetProcessId}.");
        }
    }

    private SafeFileHandle GetProcessHandle(uint processId, int access)
    {
        return NativeMethods.OpenProcess_SafeHandle((PROCESS_ACCESS_RIGHTS)access, false, processId) ?? throw new UnauthorizedAccessException($"Failed to open process handle with access {access}.");
    }


    public void InjectModule(string modulePath)
    {
        CreateThread(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll"), "LoadLibraryW", ref modulePath);
    }

    /// <summary>
    /// Create a thread to execute a function within a module.
    /// </summary>
    /// <param name="module">The name of the module containing the desired function.</param>
    /// <param name="function">The name of the exported function we will call.</param>
    /// <param name="arguments">Serialized arguments for passing to the module function.</param>
    /// <param name="waitForThreadExit">We can wait for the thread to exit and then deallocate any memory
    /// we allocated or return immediately and deallocate the memory in a separate call.</param>
    /// <returns>The address containing the allocated memory for the function arguments.</returns>
    public nint CreateThread<T>(string module, string function, ref T arguments, bool waitForThreadExit = true)
    {
        SafeHandle? remoteThread = null;
        Memory.MemoryAllocation? argumentsAllocation = null;

        try
        {
            argumentsAllocation = _memoryManager.AllocateAndCopy(arguments, !waitForThreadExit);

            // Execute the function call in a new thread
            remoteThread = CreateRemoteThread(module, function, argumentsAllocation.Address);

            if (waitForThreadExit)
            {
                NativeMethods.WaitForSingleObject(remoteThread, uint.MaxValue);
            }

            return argumentsAllocation.Address;
        }
        finally
        {
            remoteThread?.Dispose();
            if (waitForThreadExit && argumentsAllocation is not null)
            {
                _memoryManager.Deallocate(argumentsAllocation);
            }
        }
    }

    private unsafe SafeHandle? GetModuleHandle(string moduleName)
    {
        SafeHandle[] moduleHandles = GetProcessModuleHandles();
        var chars = new char[260];

        // Starting from the end as the module should be one of the latest that has been loaded
        for (var i = moduleHandles.Length - 1; i >= 0; i--)
        {
            var moduleHandle = moduleHandles[i];
            uint length;

            fixed (char* name = chars)
            {
                length = NativeMethods.GetModuleFileNameEx(SafeHandle, moduleHandle, name, (uint)chars.Length);
                if (length == 0)
                {
                    continue;
                }
            }

            //if (length == moduleName.Length && new ReadOnlySpan<char>(chars).TrimStart(new char[] { '\\', '\\', '?', '\\' }).Equals(moduleName, StringComparison.OrdinalIgnoreCase))
            //{
            //    return moduleHandle;
            //}

            var moduleFileName = length >= 4 && chars[0..4] is ['\\', '\\', '?', '\\'] ?
                    new string(chars, 4, (int)length - 4) :
                    new string(chars, 0, (int)length);

            if (moduleName.Equals(moduleFileName, StringComparison.OrdinalIgnoreCase))
            {
                return moduleHandle;
            }
        }

        return null;
    }

    private unsafe SafeHandle[] GetProcessModuleHandles()
    {
        uint moduleCount = 0;

        var hmod = new HMODULE[100];
        // TODO: Not sure about that loop...
        for (; ; )
        {
            bool enumResult = false;
            // Attempt an arbitrary amount of times since EnumProcessModulesEx can fail
            // as a result of regular OS operations.
            for (int i = 0; i < 100; i++)
            {
                //TODO: test
                var unsafeHandle = new HANDLE(SafeHandle.DangerousGetHandle());
                var addr = (HMODULE*)Marshal.UnsafeAddrOfPinnedArrayElement(hmod, 0);

                enumResult = NativeMethods.EnumProcessModulesEx(unsafeHandle, addr, (uint)(sizeof(HMODULE) * hmod.Length), &moduleCount, ENUM_PROCESS_MODULES_EX_FLAGS.LIST_MODULES_ALL);
                if (enumResult)
                {
                    break;
                }
                Thread.Sleep(1);
            }

            if (!enumResult)
            {
                throw new Win32Exception("Failed to retrieve process modules.");
            }

            moduleCount = (uint)(moduleCount / sizeof(HMODULE));

            var allFound = moduleCount <= hmod.Length;

            Array.Resize(ref hmod, (int)moduleCount);

            if (allFound)
            {
                break;
            }
        }

        return hmod.Select(hm => new SafeFileHandle(hm.Value, false)).ToArray();
    }

    private unsafe SafeHandle CreateRemoteThread(string module, string function, nint parameter)
    {
        nint startAddress = GetProcAddress(module, function);

        return CreateRemoteThread(SafeHandle, nint.Zero, nuint.Zero, startAddress, parameter, 0, nint.Zero);
    }

    public unsafe nint GetProcAddress(string module, string function)
    {
        var moduleHandle = GetModuleHandle(module);

        if (moduleHandle is null)
        {
            throw new Win32Exception($"Failed to get the {module} handle.");
        }

        MODULEINFO moduleInfo = GetModuleInfo(moduleHandle);

        return PEImage.CreateForProcessModule(SafeHandle, (nint)moduleInfo.lpBaseOfDll)
                      .GetExportedFunctions()
                      .FirstOrDefault(entry => entry.Name == function)
                      .Address;
    }


    private unsafe MODULEINFO GetModuleInfo(SafeHandle moduleHandle)
    {
        if (!NativeMethods.GetModuleInformation(SafeHandle, moduleHandle, out MODULEINFO moduleInfo, (uint)sizeof(MODULEINFO)))
        {
            throw new Win32Exception("Failed to get process module information");
        }
        return moduleInfo;
    }

    public void Dispose()
    {
        _memoryManager?.Dispose();
        GC.SuppressFinalize(this);
    }

    ~ManagedProcess() => Dispose();
}
