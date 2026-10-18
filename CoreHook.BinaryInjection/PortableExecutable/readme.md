# Wokhan.PEImage: an in-memory PortableExecultable (PE) image "reader"

> :information_source: All structures and descriptions themselves comes directly from the Microsoft PE Format specification available at 
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format \
The goal of this library is to provide a light and efficient way to read PEImage without allocating anything (directly mapping to blittable structs). There are other parsers out there (even one in System.Reflection.PortableExecutable I used some enums from), but I wanted to play around with direct memory access as I really like that subject ;)
