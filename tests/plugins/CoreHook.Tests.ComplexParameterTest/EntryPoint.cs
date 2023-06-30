﻿using System;

using CoreHook.EntryPoint;

namespace CoreHook.Tests.ComplexParameterTest;

public class EntryPoint : IEntryPoint
{
    public EntryPoint(ComplexParameter _) { }

    public void Run(ComplexParameter complexParameter)
    {
        Console.WriteLine(complexParameter.Message);
        Console.WriteLine(complexParameter.HostProcessId);
    }
}
