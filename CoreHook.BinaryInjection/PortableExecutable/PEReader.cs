using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace CoreHook.BinaryInjection.PortableExecutable;

public class PEReader
{
    SafeHandle? SafeHandle;
    nint ModuleBaseAddress;

    internal PEReader(SafeHandle? handle, nint moduleBaseAddress)
    {
        ModuleBaseAddress = moduleBaseAddress;
        SafeHandle = handle;
    }

    internal unsafe T Read<T>(nint rva) where T : new() 
    {
        if (SafeHandle is not null)
        {
            var ret = new T();

            CopyProcessMemory(rva, &ret, (uint)sizeof(T));

            return ret;
        }
        else
        {
            return *(T*)(ModuleBaseAddress + rva);
        }
    }

    internal unsafe TElement[] ReadArray<TElement>(nint rva, Func<TElement, bool> stopCondition, int maxLength = 256) where TElement : new()
    {
        List<TElement> arrayItems = new();

        uint cpt = 0;
        bool keepGoing;

        do
        {
            var item = Read<TElement>(rva);

            keepGoing = !stopCondition(item);

            if (keepGoing)
            {
                cpt++;

                arrayItems.Add(item);
                rva = rva + sizeof(TElement);
            }
        } while (keepGoing && cpt < maxLength);

        return arrayItems.ToArray();
    }

    internal unsafe TElement[] ReadArray<TElement>(nint rva, uint len)
    {
        if (SafeHandle is not null)
        {
            var array = new TElement[len];
            fixed (TElement* ptr = array)
            {
                CopyProcessMemory(rva, ptr, (uint)(len * sizeof(TElement)));
            }
            return array;
        }
        else
        {
            return new Span<TElement>((void*)(ModuleBaseAddress + rva), (int)len).ToArray();
        }
    }

    private unsafe void CopyProcessMemory(nint rva, void* buffer, uint? len)
    {
        var bytesRead = new nuint();
        if (!NativeMethods.ReadProcessMemory(SafeHandle, (void*)(ModuleBaseAddress + rva), buffer, (nuint)len, &bytesRead) || bytesRead != len)
        {
            throw new Win32Exception($"Failed to read process memory at {rva:X16}.");
        }
    }

    internal unsafe string ReadStringANSI(nint rva, int maxLength = 4096)
    {
        nint address;
        if (SafeHandle is not null)
        {
            // We have to copy the memory buffer using marshalling (hence the indirect PtrToStringAnsi call).
            // Maybe use CopyMemory and release the copied data next?
            fixed (sbyte* bufferPtr = new sbyte[maxLength])
            {
                CopyProcessMemory(rva, bufferPtr, (uint)maxLength);
                address = (nint)bufferPtr;
            }
        }
        else
        {
            address = ModuleBaseAddress + rva;
        }

        return Marshal.PtrToStringAnsi(address);
    }

}
