﻿using CoreHook.Unmanaged;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace CoreHook.BinaryInjection
{
    [StructLayout(LayoutKind.Explicit)]
    public struct FunctionCallArgs
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = FunctionNameMaxWide)]
        public byte[] Assembly;

        [FieldOffset(512)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = FunctionNameMaxWide)]
        public byte[] Class;

        [FieldOffset(1024)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = FunctionNameMaxWide)]
        public byte[] Function;

        [FieldOffset(1536)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = BinaryArgumentsSize)]
        public byte[] Arguments;

        private const int FunctionNameMax = 256;
        private const int FunctionNameMaxWide = FunctionNameMax*2;

        private const int BinaryArgumentsSize = 512;
        private const int FunctionNamePartsMin = 3;

        public FunctionCallArgs(string classFunctionName, byte[] arguments = null)
        {
            if(classFunctionName == null)
            {
                throw new ArgumentNullException(classFunctionName);
            }
      
            var args = classFunctionName.Split('.');
            if (args.Length < FunctionNamePartsMin)
            {
                throw new ArgumentException("invalid class and function name");
            }

            string assembly = "";
            var argsCount = args.Length - 2;
            for (var x = 0; x < argsCount; x++)
            {        
                assembly += args[x];
                if (x != argsCount - 1)
                {
                    assembly += ".";
                }
            }
            var type = args[argsCount++];
            var function = args[argsCount];

            Assembly = Encoding.Unicode.GetBytes(assembly.PadRight(FunctionNameMax, '\0'));
            Class = Encoding.Unicode.GetBytes(string.Format("{0}.{1}", assembly, type).PadRight(FunctionNameMax, '\0'));
            Function = Encoding.Unicode.GetBytes(function.PadRight(FunctionNameMax, '\0'));
            Arguments = arguments ?? new byte[BinaryArgumentsSize];
        }

        public FunctionCallArgs(string classFunctionName, IntPtr arguments)
        {
            if (classFunctionName == null)
            {
                throw new ArgumentNullException(classFunctionName);
            }

            var args = classFunctionName.Split('.');
            if (args.Length < FunctionNamePartsMin)
            {
                throw new ArgumentException("invalid class and function name");
            }
            string assembly = "";
            var argsCount = args.Length - 2;
            for (var x = 0; x < argsCount; x++)
            {
                assembly += args[x];
                if (x != argsCount - 1)
                {
                    assembly += ".";
                }
            }
            var type = args[argsCount++];
            var function = args[argsCount];

            Assembly = Encoding.Unicode.GetBytes(assembly.PadRight(FunctionNameMax, '\0'));
            Class = Encoding.Unicode.GetBytes(string.Format("{0}.{1}", assembly, type).PadRight(FunctionNameMax, '\0'));
            Function = Encoding.Unicode.GetBytes(function.PadRight(FunctionNameMax, '\0'));
            Arguments = arguments != null ? Binary.StructToByteArray(arguments, BinaryArgumentsSize) : new byte[BinaryArgumentsSize];
        }

        public FunctionCallArgs(string classFunctionName, RemoteFunctionArgs arguments)
        {
            if (classFunctionName == null)
            {
                throw new ArgumentNullException(classFunctionName);
            }

            var args = classFunctionName.Split('.');
            if (args.Length < FunctionNamePartsMin)
            {
                throw new ArgumentException("invalid class and function name");
            }
            string assembly = "";
            var argsCount = args.Length - 2;
            for (var x = 0; x < argsCount; x++)
            {
                assembly += args[x];
                if (x != argsCount - 1)
                {
                    assembly += ".";
                }
            }
            var type = args[argsCount++];
            var function = args[argsCount];

            Assembly = Encoding.Unicode.GetBytes(assembly.PadRight(FunctionNameMax, '\0'));
            Class = Encoding.Unicode.GetBytes(string.Format("{0}.{1}", assembly, type).PadRight(FunctionNameMax, '\0'));
            Function = Encoding.Unicode.GetBytes(function.PadRight(FunctionNameMax, '\0'));
            Arguments = Binary.StructToByteArray(arguments, BinaryArgumentsSize);
        }
        public FunctionCallArgs(string assembly, string type, string function, byte[] arguments = null)
        {
            if (assembly == null)
            {
                throw new ArgumentNullException(assembly);
            }
            if (type == null)
            {
                throw new ArgumentNullException(type);
            }
            if (function == null)
            {
                throw new ArgumentNullException(function);
            }

            Assembly = Encoding.Unicode.GetBytes(assembly.PadRight(FunctionNameMax, '\0'));
            Class = Encoding.Unicode.GetBytes(string.Format("{0}.{1}", assembly,type).PadRight(FunctionNameMax, '\0'));
            Function = Encoding.Unicode.GetBytes(function.PadRight(FunctionNameMax, '\0'));
            Arguments = arguments ?? new byte[BinaryArgumentsSize];
        }
    }
}