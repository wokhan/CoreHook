using CoreHook.HookDefinition;
using CoreHook.Tests.ComplexParameterTest;

using Microsoft.Extensions.Logging;

using System;
using System.Diagnostics;
using System.IO;

using System.Reflection;
using System.Threading;

namespace CoreHook.Tests.HookDefinition;

[Collection("Remote Injection Tests")]
public class RemoteHookTest
{
    private ILoggerFactory logger = LoggerFactory.Create(config => config.AddSimpleConsole());

    [Theory]
    [InlineData("System32")]
    [InlineData("SysWOW64")]
    public void InjectDllIntoTargetTest(string applicationFolder)
    {
        const string testHookLibrary = "CoreHook.Tests.SimpleParameterTest.dll";
        const string remoteArgument = "Berner";

        var testProcess = StartProcess(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), applicationFolder, "notepad.exe"));

        Thread.Sleep(500);

        Assert.True(RemoteHook.InjectDllIntoTarget(testProcess, GetTestDllPath(testHookLibrary), typeof(SimpleParameterTest.EntryPoint).FullName, logger, PipePlatformBase.Instance, remoteArgument));

        Assert.Equal(remoteArgument, ReadLineFromProcess(testProcess));

        EndProcess(testProcess);
    }
    //}

    //[Collection("Remote Injection Tests")]
    //public class RemoteInjectionTestComplexParameter
    //{
    [Theory]
    [InlineData("System32")]
    [InlineData("SysWOW64")]
    public void InjectDllIntoTargetComplexTest(string applicationFolder)
    {
        const string testHookLibrary = "CoreHook.Tests.ComplexParameterTest.dll";
        const string testMessageParameter = "Berner";

        var complexParameter = new ComplexParameter
        {
            Message = testMessageParameter,
            HostProcessId = Environment.ProcessId
        };

        var testProcess = StartProcess(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), applicationFolder, "notepad.exe"));

        Thread.Sleep(500);

        Assert.True(RemoteHook.InjectDllIntoTarget(testProcess, GetTestDllPath(testHookLibrary), typeof(EntryPoint).FullName, logger, PipePlatformBase.Instance, complexParameter));

        Assert.Equal(complexParameter.Message, ReadLineFromProcess(testProcess));
        Assert.Equal(complexParameter.HostProcessId.ToString(), ReadLineFromProcess(testProcess));

        EndProcess(testProcess);
    }

    private static string GetTestDllPath(string dllName)
    {
        return Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), dllName);
    }

    private static Process StartProcess(string fileName)
    {
        var testProcess = new Process
        {
            StartInfo =
                {
                    FileName = fileName,
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true
                }
        };

        testProcess.Start();

        return testProcess;
    }

    private static void EndProcess(Process process)
    {
        process?.Kill(true);
    }

    private static string ReadLineFromProcess(Process target)
    {
        return target.StandardOutput.ReadLine();
    }

}
