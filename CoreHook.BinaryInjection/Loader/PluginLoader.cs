﻿using CoreHook.BinaryInjection.NativeDTO;
using Microsoft.Extensions.Logging;

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Text.Json;
using System.Threading.Tasks;

namespace CoreHook.Loader;

public class PluginLoader
{
    private static readonly ILoggerFactory _loggerFactory = LoggerFactory.Create(builder => builder.AddDebug());
    private static readonly ILogger _logger = _loggerFactory.CreateLogger<PluginLoader>();
    
    public static AssemblyDelegate DefaultDelegate { get; } = new(typeof(PluginLoader).GetMethod(nameof(Load))!);

    /// <summary>
    /// Initialize the plugin dependencies and execute its entry point.
    /// </summary>
    /// <param name="remoteInfoAddr">Parameters containing the plugin to load and the parameters to pass to it's entry point.</param>
    /// <returns>A status code representing the plugin initialization state.</returns>
    [UnmanagedCallersOnly]//(CallConvs = new[] { typeof(CallConvCdecl) })]
    public static int Load(IntPtr payLoadPtr)
    {
        NotificationHelper? hostNotifier = null;
        try
        {
            if (payLoadPtr == IntPtr.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(payLoadPtr), "Remote arguments address was zero");
            }

            var payLoadStr = Marshal.PtrToStringUni(payLoadPtr)!;

            var payLoad = JsonSerializer.Deserialize<ManagedRemoteInfo>(payLoadStr, new JsonSerializerOptions() { IncludeFields = true });

            payLoad.UserParams = payLoad.UserParams?.Zip(payLoad.UserParamsTypeNames!, (param, typeName) => param is null ? null : ((JsonElement)param).Deserialize(Type.GetType(typeName, true))).ToArray() ?? Array.Empty<object>();

            // Start the IPC message notifier with a connection to the host application.
            hostNotifier = new NotificationHelper(payLoad.ChannelName, _logger);

            _ = hostNotifier.Log($"Loading plugin: {payLoad.UserLibrary}.");

            _ = hostNotifier.Log("Resolving dependencies...");

            // Execute the plugin library's entry point and pass in the user arguments.
            var loadPluginTask = LoadPlugin(payLoad, hostNotifier);
            loadPluginTask.Wait();

            return (int)loadPluginTask.Result;
        }
        //catch (ArgumentOutOfRangeException outOfRangeEx)
        //{
        //    Log(hostNotifier, outOfRangeEx.ToString());
        //    throw;
        //}
        catch (Exception e)
        {
            _ = hostNotifier?.Log($"Unable to load plugin: {e.Message}", LogLevel.Error);
        }
        finally
        {
            hostNotifier?.Dispose();
        }

        return (int)PluginInitializationState.Failed;
    }

    /// <summary>
    /// Find the entry point of the plugin module, initialize it, and execute its Run method.
    /// </summary>
    /// <param name="assembly">The plugin assembly containing the entry point.</param>
    /// <param name="paramArray">The parameters passed to the plugin Run method.</param>
    /// <param name="hostNotifier">Used to notify the host about the state of the plugin initialization.</param>
    private static async Task<PluginInitializationState> LoadPlugin(ManagedRemoteInfo payLoad, NotificationHelper hostNotifier)
    {
        var assembly = LoadAssembly(payLoad.UserLibrary, hostNotifier);
        if (assembly is null)
        {
            _ = hostNotifier?.Log($"Unable to load assembly from {payLoad.UserLibrary}.", LogLevel.Error);
            return PluginInitializationState.Failed;
        }

        var entryPoint = assembly.GetType(payLoad.ClassName, false, false);
        if (entryPoint is null)
        {
            _ = hostNotifier?.Log($"Assembly {assembly.FullName} doesn't contain the {payLoad.ClassName} type.", LogLevel.Error);
            return PluginInitializationState.Failed;
        }

        var runMethod = entryPoint.GetMethod(payLoad.MethodName, BindingFlags.Public | BindingFlags.Instance | BindingFlags.FlattenHierarchy);
        if (runMethod is null)
        {
            _ = hostNotifier?.Log($"Failed to find the 'Run' function with {payLoad.UserParams.Length} parameter(s) in {assembly.FullName}.", LogLevel.Error);
            return PluginInitializationState.Failed;
        }

        _ = hostNotifier.Log("Found entry point, initializing plugin class.");
        var instance = Activator.CreateInstance(entryPoint, payLoad.UserParams);
        if (instance is null)
        {
            _ = hostNotifier?.Log($"Failed to find the constructor {entryPoint.Name} in {assembly.FullName}", LogLevel.Error);
            return PluginInitializationState.Failed;
        }

        _ = hostNotifier.Log("Plugin successfully initialized. Executing the plugin entry point.");

        if (await hostNotifier.SendInjectionComplete(Environment.ProcessId))
        {
            try
            {
                // Execute the plugin 'Run' entry point.
                runMethod?.Invoke(instance, BindingFlags.Public | BindingFlags.Instance | BindingFlags.ExactBinding | BindingFlags.InvokeMethod, null, payLoad.UserParams, null);
            }
            catch (Exception e)
            {
                _ = hostNotifier.Log($"Entry point execution failed: {e.Message}", LogLevel.Error);
            }
            return PluginInitializationState.Initialized;
        }

        return PluginInitializationState.Failed;
    }

    private static Assembly? LoadAssembly(string path, NotificationHelper hostNotifier)
    {
        try
        {
            _ = hostNotifier.Log($"Image base path is {Path.GetDirectoryName(path)}");

            var assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(path);

            var _assemblyResolver = new AssemblyDependencyResolver(path);
            
            var _loadContext = AssemblyLoadContext.GetLoadContext(assembly);
            _loadContext.Resolving += (context, assemblyName) =>
            {
                var path = _assemblyResolver.ResolveAssemblyToPath(assemblyName);
                return path is not null ? _loadContext.LoadFromAssemblyPath(path) : null;
            };

            return assembly;
        }
        catch (Exception e)
        {
            _ = hostNotifier.Log($"AssemblyResolver error: {e}");
        }

        return null;
    }
}
