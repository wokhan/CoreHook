﻿using CoreHook.BinaryInjection;
using CoreHook.Extensions;
using CoreHook.Helpers;
using CoreHook.IPC.Platform;
using CoreHook.Loader;
using CoreHook.Managed;

using Microsoft.Extensions.Logging;

using System;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CoreHook.HookDefinition;

/// <summary>
/// 
/// </summary>
public static class RemoteHook
{
    /// <summary>
    /// The name of the pipe used for notifying the host process
    /// if the hooking plugin has been loaded successfully in
    /// the target process or if loading failed.
    /// </summary>
    private const string InjectionPipeName = "CoreHookInjection";

    /// <summary>
    /// The .NET Assembly class that loads the .NET plugin, resolves any references, and executes
    /// the IEntryPoint.Run method for that plugin.
    /// </summary>
    private static readonly AssemblyDelegate CoreHookLoaderDelegate = new("CoreHook", "CoreHook.Loader.PluginLoader", "Load", "CoreHook.Loader.PluginLoader+LoadDelegate, CoreHook");
        
    /// <summary>
    /// Check if a file path is valid, otherwise throw an exception.
    /// </summary>
    /// <param name="filePath">Path to a file or directory to validate.</param>
    private static void ValidateFilePath(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException($"Invalid file path {filePath}");
        }
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"File path {filePath} does not exist");
        }
    }

    /// <summary>
    /// Inject and load the CoreHook hooking module <paramref name="injectionLibrary"/>
    /// in the existing created process referenced by <paramref name="targetProcessId"/>.
    /// </summary>
    /// <param name="targetProcessId">The target process ID to inject and load plugin into.</param>
    /// <param name="logger"></param>
    /// <param name="hookLibrary"></param>
    /// <param name="pipePlatform"></param>
    /// <param name="parameters"></param>
    public static bool InjectDllIntoTarget(int targetProcessId, string hookLibrary, ILoggerFactory loggerFactory, IPipePlatform? pipePlatform = null, params object[] parameters)
    {
        var logger = loggerFactory.CreateLogger("RemoteHook");

        ValidateFilePath(hookLibrary);
        logger.LogInformation($"Hook library '{hookLibrary}' found. Injecting.");

        pipePlatform ??= IPipePlatform.Default;

        var process = Process.GetProcessById(targetProcessId);
        var is64Bits = process.Is64Bit();
        logger.LogInformation($"Process #{targetProcessId} is '{(is64Bits ? "64bits" : "32bits")}.");

        var (coreRootPath, coreLoadPath, coreRunPath, corehookPath, hostpath) = ModulesPathHelper.GetCoreLoadPaths(is64Bits);
        logger.LogInformation($".NET Path: {coreRootPath}\r\nLoader path: {coreLoadPath}\r\nRunner path: {coreRunPath}\r\nDetours lib path: {corehookPath}\r\nHost: {hostpath}");

        if (process.IsPackagedApp(out string _))
        {
            // Make sure the native dll modules can be accessed by the UWP application
            GrantAllAppPackagesAccessToFile(coreRunPath);
            GrantAllAppPackagesAccessToFile(corehookPath);
        }

        using var injector = new RemoteInjector(targetProcessId, pipePlatform, InjectionPipeName, loggerFactory);

        var startCoreCLRArgs = new NetHostStartArguments(coreLoadPath, coreRootPath, InjectionPipeName);
        if (injector.Inject(coreRunPath, "StartCoreCLR", startCoreCLRArgs, true, hostpath, corehookPath))
        {
            logger.LogInformation($"Successfully started the .NET CLR in the target process.");

            var managedFuncArgs = new ManagedFunctionArguments(CoreHookLoaderDelegate, InjectionPipeName, new ManagedRemoteInfo(Environment.ProcessId, InjectionPipeName, Path.GetFullPath(hookLibrary), parameters));
            if (injector.Inject(coreRunPath, "ExecuteAssemblyFunction", managedFuncArgs, false))
            {
                logger.LogInformation($"Successfully executed target .NET method.");
                return true;
            }
        }

        return false;
    }

    private static readonly SecurityIdentifier AllAppPackagesSid = new SecurityIdentifier("S-1-15-2-1");

    //TODO: move in a utility class with conditional compilation for UWP
    /// <summary>
    /// Grant ALL_APPLICATION_PACKAGES permissions to a file at <paramref name="fileName"/>.
    /// </summary>
    /// <param name="fileName">The file to be granted ALL_APPLICATION_PACKAGES permissions.</param>
    private static void GrantAllAppPackagesAccessToFile(string fileName)
    {
        try
        {
            var fileInfo = new FileInfo(fileName);
            FileSecurity acl = fileInfo.GetAccessControl();

            var rule = new FileSystemAccessRule(AllAppPackagesSid, FileSystemRights.ReadAndExecute, AccessControlType.Allow);
            acl.SetAccessRule(rule);

            fileInfo.SetAccessControl(acl);
        }
        catch
        {
        }
    }

}