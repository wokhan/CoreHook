using System;
using System.Runtime.InteropServices;
using Xunit;
using Windows.Win32;
using CoreHook.Extensions;
using CoreHook.HookDefinition;

namespace CoreHook.Tests.Windows;

[Collection("Local Hook Tests")]
public class LocalHookTest
{
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool BeepDelegate(uint dwFreq, uint dwDuration);

    private bool _beepHookCalled;

    [return: MarshalAs(UnmanagedType.Bool)]
    private bool Detour_Beep(uint dwFreq, uint dwDuration)
    {
        _beepHookCalled = true;

        NativeMethods.Beep(dwFreq, dwDuration);
        return false;
    }

    [Fact]
    public void ShouldInstallDetourToFunctionAddress()
    {
        using (var hook = LocalHook.Create("kernel32.dll", "Beep", new BeepDelegate(Detour_Beep), this))
        {
            _beepHookCalled = false;

            hook.ThreadACL.SetInclusiveACL(new int[] { 0 });

            Assert.False(NativeMethods.Beep(100, 100));

            Assert.True(_beepHookCalled);
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate uint GetTickCountDelegate();

    [DllImport("Kernel32.dll")]
    public static extern uint GetTickCount();

    private bool _getTickCountCalled;

    private uint Detour_GetTickCount()
    {
        _getTickCountCalled = true;

        return 0;
    }

    [Fact]
    public void ShouldBypassDetourWithCallToOriginalFunction()
    {
        using (var hook = LocalHook.Create("kernel32.dll", "GetTickCount", new GetTickCountDelegate(Detour_GetTickCount), this))
        {
            _getTickCountCalled = false;

            hook.ThreadACL.SetInclusiveACL(new int[] { 0 });

            var getTickCount = hook.OriginalAddress.ToFunction<GetTickCountDelegate>();

            Assert.NotEqual<uint>(0, getTickCount());

            Assert.False(_getTickCountCalled);
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate ulong GetTickCount64Delegate();

    private bool _getTickCount64Called;

    private ulong Detour_GetTickCount64()
    {
        _getTickCount64Called = true;

        return 0;
    }

    [Fact]
    public void ShouldBypassInstalledFunctionDetour()
    {
        using (var hook = LocalHook.Create("kernel32.dll", "GetTickCount64", new GetTickCount64Delegate(Detour_GetTickCount64), this))
        {
            _getTickCount64Called = false;

            hook.ThreadACL.SetInclusiveACL(new int[] { 0 });

            Assert.Equal<ulong>(0, NativeMethods.GetTickCount64());

            Assert.True(_getTickCount64Called);

            _getTickCount64Called = false;

            var getTickCount64 = hook.OriginalAddress.ToFunction<GetTickCount64Delegate>();

            Assert.NotEqual<ulong>(0, getTickCount64());

            Assert.False(_getTickCount64Called);
        }
    }

    [Fact]
    public void Invalid_LocalHook_Create_Detour_Delegate_Throws_ArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => LocalHook.Create("kernel32.dll", "CreateFileW", null, this));
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool QueryPerformanceCounterDelegate(out long performanceCount);

    private bool Detour_QueryPerformanceCounter(out long performanceCount)
    {
        performanceCount = 0;

        return false;
    }

    [Fact]
    public void ShouldCreateNullDetourCallback()
    {
        using (var hook = LocalHook.Create("kernel32.dll", "QueryPerformanceCounter", new QueryPerformanceCounterDelegate(Detour_QueryPerformanceCounter), null))
        {
            Assert.Null(hook.Callback);
            Assert.NotNull(hook.ThreadACL);
            Assert.NotNull(hook.OriginalAddress);
            Assert.NotEqual(IntPtr.Zero, hook.OriginalAddress);
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate uint GetVersionDelegate();

    private uint Detour_GetVersion() => 0;
}
