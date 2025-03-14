﻿using CoreHook.Extensions;
using CoreHook.HookDefinition;

using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

using Windows.Win32;

using Xunit;

namespace CoreHook.Tests.Windows;

[Collection("Local Hook Tests")]
public class SymbolsTest
{
    //TODO: check why CsWin32 uses PWSTR for managed calls instead of taking care of marshaling
    [DllImport("KERNEL32.dll", ExactSpelling = true, EntryPoint = "GetAtomNameW", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [SupportedOSPlatform("windows5.0")]
    internal static extern uint GetAtomName(ushort nAtom, StringBuilder lpBuffer, int nSize);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate ushort AddAtomWDelegate(string lpString);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate ushort InternalAddAtomDelegate(bool local, bool unicode, string atomName, int arg4);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate ushort InternalFindAtom(bool local, bool unicode, string atomName);

    private InternalAddAtomDelegate InternalAddAtomFunction;
    private InternalFindAtom InternalFindAtomFunction;

    private bool _internalAddAtomCalled;
    private bool _internalFindAtomCalled;
    private bool _addAtomCalled;

    // The default MAX_PATH file system string size for Windows.
    // A new opt-in, long path limit was added in Windows 10, version 1607.
    private const int MaxPathLength = 260;

    private ushort Detour_InternalAddAtomHook(bool local,
        bool unicode, string atomName, int arg4)
    {
        _internalAddAtomCalled = true;

        return InternalAddAtomFunction(local, unicode, atomName, arg4);
    }

    private ushort Detour_AddAtom(string atomName)
    {
        _addAtomCalled = true;

        return NativeMethods.AddAtom(atomName);
    }

    /// <summary>
    /// Detour a private function and call the internal function 
    /// using the detour bypass address to skip the detour barrier call.
    /// </summary>
    [Fact]
    public void ShouldDetourInternalFunction()
    {
        using (var hook = LocalHook.Create("kernel32.dll", "InternalAddAtom", new InternalAddAtomDelegate(Detour_InternalAddAtomHook), this))
        {
            InternalAddAtomFunction = hook.OriginalAddress.ToFunction<InternalAddAtomDelegate>();

            hook.ThreadACL.SetInclusiveACL(new int[] { 0 });

            _internalAddAtomCalled = false;

            string atomName = "TestLocalAtomName";
            ushort atomId = NativeMethods.AddAtom(atomName);

            Assert.NotEqual(0, atomId);
            Assert.True(_internalAddAtomCalled);

            StringBuilder atomBuffer = new StringBuilder(MaxPathLength);
            
            uint bufLength = GetAtomName(atomId, atomBuffer, MaxPathLength);
            string retrievedAtomName = atomBuffer.ToString();

            Assert.Equal((uint)atomName.Length, bufLength);
            Assert.Equal(retrievedAtomName.Length, atomName.Length);

            Assert.Equal(retrievedAtomName, atomName);

            Assert.Equal<ushort>(0, NativeMethods.DeleteAtom(atomId));
        }
    }

    /// <summary>
    /// Detour a private function and call the function's direct address
    /// when the detour is called without skipping the detour barrier.
    /// </summary>
    [Fact]
    public void ShouldDetourApiAndInternalFunctionCalledByAddAtom()
    {
        // Create the internal function and public API detours.
        using (var hookInternal = LocalHook.Create("kernel32.dll", "InternalAddAtom", new InternalAddAtomDelegate(Detour_InternalAddAtomHook), this))
        using (var hookApi = LocalHook.Create("kernel32.dll", "AddAtomW", new AddAtomWDelegate(Detour_AddAtom), this))
        {
            hookInternal.ThreadACL.SetInclusiveACL(new int[] { 0 });
            InternalAddAtomFunction = hookInternal.TargetAddress.ToFunction<InternalAddAtomDelegate>();

            hookApi.ThreadACL.SetInclusiveACL(new int[] { 0 });

            _internalAddAtomCalled = false;
            _addAtomCalled = false;

            string atomName = "TestLocalAtomName";
            ushort atomId = NativeMethods.AddAtom(atomName);

            Assert.NotEqual(0, atomId);
            Assert.True(_internalAddAtomCalled);
            Assert.True(_addAtomCalled);

            StringBuilder atomBuffer = new StringBuilder(MaxPathLength);
            uint bufLength = GetAtomName(atomId, atomBuffer, MaxPathLength);
            string retrievedAtomName = atomBuffer.ToString();

            Assert.NotEqual<uint>(0, bufLength);
            Assert.Equal((uint)atomName.Length, bufLength);
            Assert.Equal(retrievedAtomName.Length, atomName.Length);

            Assert.Equal(retrievedAtomName, atomName);

            Assert.Equal<ushort>(0, NativeMethods.DeleteAtom(atomId));
        }
    }

    [Fact]
    public void ShouldDetourApiIAndInternalFunctionUsingBypassAddress()
    {
        using (var hookInternal = LocalHook.Create("kernel32.dll", "InternalAddAtom", new InternalAddAtomDelegate(Detour_InternalAddAtomHook), this))
        using (var hookApi = LocalHook.Create("kernel32.dll", "AddAtomW", new AddAtomWDelegate(Detour_AddAtom), this))
        {
            hookInternal.ThreadACL.SetInclusiveACL(new int[] { 0 });

            hookApi.ThreadACL.SetInclusiveACL(new int[] { 0 });

            InternalAddAtomFunction = hookInternal.OriginalAddress.ToFunction<InternalAddAtomDelegate>();

            _internalAddAtomCalled = false;
            _addAtomCalled = false;

            string atomName = "TestLocalAtomName";
            ushort atomId = NativeMethods.AddAtom(atomName);

            Assert.NotEqual(0, atomId);
            Assert.True(_internalAddAtomCalled);
            Assert.True(_addAtomCalled);

            StringBuilder atomBuffer = new StringBuilder(MaxPathLength);
            uint bufLength = GetAtomName(atomId, atomBuffer, MaxPathLength);
            string retrievedAtomName = atomBuffer.ToString();

            Assert.NotEqual<uint>(0, bufLength);
            Assert.Equal((uint)atomName.Length, bufLength);
            Assert.Equal(retrievedAtomName.Length, atomName.Length);

            Assert.Equal(retrievedAtomName, atomName);

            Assert.Equal<ushort>(0, NativeMethods.DeleteAtom(atomId));
        }
    }

    ushort Detour_InternalFindAtom(bool local, bool unicode, string atomName)
    {
        _internalFindAtomCalled = true;

        return InternalFindAtomFunction(local, unicode, atomName);
    }

    private delegate ulong GetCurrentNlsCacheDelegate();

    private GetCurrentNlsCacheDelegate GetCurrentNlsCacheFunction;

    private bool _GetCurrentNlsCacheCalled;

    private const int LOCALE_USER_DEFAULT = 0x400;

    // Case sensitive compare
    private const int NORM_LINGUISTIC_CASING = 0x08000000;

    // The string indicated by lpString1 is greater in lexical value
    // than the string indicated by lpString2.
    private const int CSTR_GREATER_THAN = 3;

    private ulong Detour_GetCurrentNlsCache()
    {
        _GetCurrentNlsCacheCalled = true;

        return GetCurrentNlsCacheFunction();
    }

    [Fact]
    public void ShouldDetourInternalFunctionCalledByCompareString()
    {
        _GetCurrentNlsCacheCalled = false;

        using (var hook = LocalHook.Create("kernelbase.dll", "GetCurrentNlsCache", new GetCurrentNlsCacheDelegate(Detour_GetCurrentNlsCache), this))
        {
            hook.ThreadACL.SetInclusiveACL(new int[] { 0 });
            GetCurrentNlsCacheFunction = hook.OriginalAddress.ToFunction<GetCurrentNlsCacheDelegate>();

            string stringA = "HelloWorld";
            string stringB = "Hello";

            int comparisonResult = (int)NativeMethods.CompareString((uint)LOCALE_USER_DEFAULT, (uint)NORM_LINGUISTIC_CASING, stringA, stringA.Length, stringB, stringB.Length);

            Assert.Equal(CSTR_GREATER_THAN, comparisonResult);
            Assert.True(_GetCurrentNlsCacheCalled);
        }
    }

    [Fact]
    public void Find_Invalid_Export_Function_Throws_MissingMethodException()
    {
        Assert.Throws<MissingMethodException>(() => LocalHook.GetProcAddress("kernel32.dll", "ThisFunctionDoesNotExist"));
    }

    [Fact]
    public void Find_Invalid_Export_Module_Throws_MissingMethodException()
    {
        Assert.Throws<MissingMethodException>(() => LocalHook.GetProcAddress("UnknownModule.dll", "CreateFileW"));
    }

    [Fact]
    public void Find_Invalid_Export_ModuleFunction_Throws_MissingMethodException()
    {
        Assert.Throws<MissingMethodException>(() => LocalHook.GetProcAddress("UnknownModule.dll", "ThisFunctionDoesNotExist"));
    }
}
