# klwin
A loader for windows drivers in Linux userspace

## How it works

klwin parses a Windows driver PE file and loads it into memory. The proper memory protections are set so that it can run. Windows kernel symbols are resolved to a Linux shared object that supplies custom implementations of Windows kernel functions. The C code then uses an assembly stub to jump to driver entry.

## What is it useful for?

It's useful for reverse engineering Windows drivers. Obviously, this is not a complete emulator and Windows drivers can't be expected to just run. You can however use a debugger to step through specific functions to see what they are doing.
