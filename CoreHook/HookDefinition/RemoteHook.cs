using CoreHook.BinaryInjection;
using CoreHook.BinaryInjection.NativeDTO;
using CoreHook.IPC.Platform;
using CoreHook.Loader;

using Microsoft.Extensions.Logging;

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace CoreHook.HookDefinition;

/// <summary>
/// 
/// </summary>
public static class RemoteHook
{
    /// <summary>
    /// The name of the native detour module for 64-bit processes.
    /// </summary>
    private const string CoreHookingModule64 = "x64\\corehook64.dll";

    /// <summary>
    /// The name of the native detour module for 32-bit processes.
    /// </summary>
    private const string CoreHookingModule32 = "x86\\corehook32.dll";

    /// <summary>
    /// The name of the pipe used for notifying the host process
    /// if the hooking plugin has been loaded successfully in
    /// the target process or if loading failed.
    /// </summary>
    private const string PIPE_NAME_BASE = "CoreHookInjection_";

    /// <summary>
    /// Inject and load the CoreHook hooking module <paramref name="injectionLibrary"/>
    /// in the existing created process referenced by <paramref name="targetProcessId"/>.
    /// </summary>
    /// <param name="targetProcessId">The target process ID to inject and load plugin into.</param>
    /// <param name="logger"></param>
    /// <param name="hookLibrary"></param>
    /// <param name="pipePlatform"></param>
    /// <param name="parameters"></param>
    public static bool InjectDllIntoTarget(Process targetProcess, string hookLibrary, string hookType, ILoggerFactory loggerFactory, IPipePlatform? pipePlatform = null, params object[] parameters)
    {
        var logger = loggerFactory.CreateLogger("RemoteHook");

        if (!File.Exists(hookLibrary))
        {
            throw new FileNotFoundException($"File path {hookLibrary} is invalid or file does not exist.");
        }

        logger.LogInformation("Hook library '{hookLibrary}' found. Injecting.", hookLibrary);

        var injectionPipeName = PIPE_NAME_BASE + targetProcess.Id;

        var corehookPath = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, targetProcess.Is64Bit() ? CoreHookingModule64 : CoreHookingModule32);
        if (!File.Exists(corehookPath))
        {
            throw new FileNotFoundException($"File path {corehookPath} is invalid or file does not exist.");
        }

        if (targetProcess.IsPackagedApp(out string _))
        {
            UwpSecurityHelper.GrantAllAppPackagesAccessToFile(corehookPath);
        }

        // Inject the native corehook libraries based on Microsoft Detours
        using var injector = new RemoteInjector(targetProcess, pipePlatform ?? IPipePlatform.Default, injectionPipeName, loggerFactory);
        injector.InjectLibraries(corehookPath);

        // CoreHook lib (this project) will now inject itself as it's also acting as a loader
        var coreLoadPath = Assembly.GetExecutingAssembly().Location;
        var args = new ManagedRemoteInfo(Environment.ProcessId, injectionPipeName, Path.GetFullPath(hookLibrary), hookType, nameof(HookBase.Run), parameters);
        return injector.InjectManaged(coreLoadPath, null, args);
    }
}
