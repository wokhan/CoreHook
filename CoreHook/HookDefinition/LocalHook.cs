﻿using System;
using System.Runtime.InteropServices;
using System.Runtime.ConstrainedExecution;
using CoreHook.Native;

namespace CoreHook.HookDefinition;

/// <summary>
/// Class for creating and managing a function hook.
/// </summary>
public class LocalHook : CriticalFinalizerObject, IDisposable
{
    protected nint Handle = nint.Zero;

    /// <summary>
    /// ACL used to activate or de-activate a detour for all threads.
    /// </summary>
    protected readonly int[] DefaultThreadAcl = new int[0];

    protected Delegate? DetourFunction;

    protected object ThreadSafe = new object();

    protected GCHandle SelfHandle;

    protected HookAccessControl AccessControl;

    /// <summary>
    /// Get the thread ACL handle for this hook.
    /// </summary>
    public HookAccessControl ThreadACL
    {
        get
        {
            if (Handle == nint.Zero)
            {
                throw new ObjectDisposedException(typeof(LocalHook).FullName);
            }

            return AccessControl;
        }
    }

    /// <summary>
    /// Context object passed in during detour creation to <see cref="Create"/>
    /// </summary>
    public object? Callback { get; protected set; }

    /// <summary>
    /// Get the address used to call the original function,
    /// bypassing the user detour.
    /// </summary>
    public nint OriginalAddress
    {
        get
        {
            if (Handle == nint.Zero)
            {
                throw new ObjectDisposedException(typeof(LocalHook).FullName);
            }

            NativeApi.DetourGetHookBypassAddress(Handle, out nint targetFunctionAddress);
            return targetFunctionAddress;
        }
    }

    /// <summary>
    /// Address of the function that is detoured.
    /// </summary>
    public nint TargetAddress { get; protected set; }

    private bool _enabled;

    /// <summary>
    /// Determines if a detour is active or inactive for all threads.
    /// </summary>
    public bool Enabled
    {
        get => _enabled;
        set
        {
            if (value)
            {
                ThreadACL.SetExclusiveACL(DefaultThreadAcl);
            }
            else
            {
                ThreadACL.SetInclusiveACL(DefaultThreadAcl);
            }
            _enabled = value;
        }
    }

    protected LocalHook() { }

    /// <summary>
    /// Get the address for a function located in a module that is loaded in the current process.
    /// </summary>
    /// <param name="module">A library name like "kernel32.dll" or a full path to the module.</param>
    /// <param name="function">The name of the function, such as "CreateFileW".</param>
    /// <returns>The address of the given function name in the process.</returns>
    public static nint GetProcAddress(string module, string function)
    {
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(function);

        nint functionAddress = NativeApi.DetourFindFunction(module, function);
        if (functionAddress == nint.Zero)
        {
            throw new MissingMethodException($"The function {function} in module {module} was not found.");
        }
        return functionAddress;
    }


    /// <summary>
    /// Install a managed hook with a managed delegate for the hook handler.
    /// </summary>
    /// <param name="targetFunction">The target function to install the detour at.</param>
    /// <param name="detourFunction">The hook handler which intercepts the target function.</param>
    /// <param name="callback">A context object that will be available for reference inside the detour.</param>
    /// <returns>The handle to the function hook.</returns>
    public static LocalHook Create(string library, string methodName, Delegate detourFunction, object callback, int[]? exclusiveACL = null)
    {
        nint targetFunction = GetProcAddress(library, methodName);

        var hook = new LocalHook
        {
            Callback = callback,
            TargetAddress = targetFunction,
            Handle = Marshal.AllocCoTaskMem(nint.Size),
            DetourFunction = detourFunction
        };

        hook.SelfHandle = GCHandle.Alloc(hook, GCHandleType.Weak);

        InstallHook(hook, targetFunction, Marshal.GetFunctionPointerForDelegate(hook.DetourFunction), GCHandle.ToIntPtr(hook.SelfHandle));
      
        hook.ThreadACL.SetExclusiveACL(exclusiveACL ?? new int[] { 0 });

        return hook;
    }

    /// <summary>
    /// Install an unmanaged hook using the pointer to a hook handler.
    /// </summary>
    /// <param name="targetFunction">The target function to install the detour at.</param>
    /// <param name="detourFunction">The hook handler which intercepts the target function.</param>
    /// <param name="callback">A context object that will be available for reference inside the detour.</param>
    /// <returns>The handle to the function hook.</returns>
    public static LocalHook CreateUnmanaged(nint targetFunction, nint detourFunction, nint callback, int[]? exclusiveACL = null)
    {
        var hook = new LocalHook
        {
            Callback = callback,
            TargetAddress = targetFunction,
            Handle = Marshal.AllocCoTaskMem(nint.Size)
        };

        hook.SelfHandle = GCHandle.Alloc(hook, GCHandleType.Weak);

        InstallHook(hook, targetFunction, detourFunction, callback);

        hook.ThreadACL.SetExclusiveACL(exclusiveACL ?? new int[] { 0 });

        return hook;
    }

    /// <summary>
    /// Install a hook handler to a target function using a pointer to a hook handler.
    /// </summary>
    /// <param name="hook">The hooking class that manages the detour.</param>
    /// <param name="targetFunction">The target function to install the detour at.</param>
    /// <param name="detourFunction">The hook handler which intercepts the target function.</param>
    /// <param name="callback">A context object that will be available for reference inside the detour.</param>
    private static void InstallHook(LocalHook hook, nint targetFunction, nint detourFunction, nint callback)
    {
        Marshal.WriteIntPtr(hook.Handle, nint.Zero);

        try
        {
            NativeApi.DetourInstallHook(targetFunction, detourFunction, callback, hook.Handle);
        }
        catch
        {
            Marshal.FreeCoTaskMem(hook.Handle);
            hook.Handle = nint.Zero;

            hook.SelfHandle.Free();

            throw;
        }

        hook.AccessControl = new HookAccessControl(hook.Handle);
    }

    private bool _disposed = false;

    /// <summary>
    /// Dispose the hook and uninstall the detour from the target function.
    /// </summary>
    public void Dispose()
    {
        lock (ThreadSafe)
        {
            if (!_disposed && Handle != nint.Zero)
            {
                _disposed = true;

                // Uninstall the detour
                NativeApi.DetourUninstallHook(Handle);

                // Release the detour's resources
                Marshal.FreeCoTaskMem(Handle);

                Handle = nint.Zero;
                DetourFunction = null;
                Callback = null;

                SelfHandle.Free();
            }
        }
    }

    /// <summary>
    /// Ensure the function hook is uninstalled and any held resources are freed.
    /// </summary>
    ~LocalHook()
    {
        Dispose();
    }
}
