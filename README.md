# Walking the PEB with Dynamic Hash Resolution

This exercise demonstrates how a 64-bit Windows process can inspect its own Process Environment Block (PEB), locate a loaded module, and resolve an exported function without calling `GetModuleHandle` or `GetProcAddress`.

The program searches the PEB loader list for `kernel32.dll`, parses the module's PE export directory, resolves `VirtualAlloc` by hash, and uses the resolved function pointer to allocate one memory page.

## Learning objectives

- Access the PEB through the x64 GS segment.
- Walk the loader's `InLoadOrderModuleList`.
- Hash ANSI and UTF-16 module and function names.
- Parse DOS, NT, and export headers from an in-memory PE image.
- Resolve an exported function dynamically and call it through a typed function pointer.

## Requirements

- Windows 64-bit
- MinGW-w64 GCC or another compiler that supports the Microsoft x64 intrinsics used by the source
- A native x64 build environment

This example is architecture-specific. It uses `__readgsqword(0x60)`, which is the x64 location of the current process PEB. The hard-coded hashes also depend on the hashing algorithm implemented in `HashString`.

## Build

From this directory, run:

```powershell
gcc -Wall -Wextra -o main.exe main.c
```

You can also use the repository's VS Code C/C++ build task while `main.c` is the active file.

## Run

```powershell
.\main.exe
```

Typical output contains addresses similar to the following. The exact values vary between processes and executions:

```text
Kernel32.dll found: 0x00007ffXXXXXXXXX
VirtualAlloc found: 0x00007ffXXXXXXXXX
Memory allocated at: 0x000001XXXXXXXXX
```

The final allocation uses `MEM_COMMIT | MEM_RESERVE` and `PAGE_EXECUTE_READWRITE` for demonstration purposes. The program does not write or execute a payload in the allocated region.

## How it works

1. Read the current process PEB from the x64 GS segment.
2. Follow `PEB->Ldr->InLoadOrderModuleList`.
3. Hash each module's base name and compare it with the `kernel32.dll` hash.
4. Validate the target module's DOS and NT signatures.
5. Walk the PE export name, ordinal, and address tables.
6. Hash each exported name until the `VirtualAlloc` hash is found.
7. Call the resolved function pointer to allocate memory.

## Limitations

- The code is intended for learning and experimentation with Windows internals, not production use.
- It assumes the documented layout used by the local Windows x64 process environment and may require updates for other architectures or unusual environments.
- It does not handle forwarded exports, malformed PE images, or every possible loader edge case.
- The project is not part of the repository-level CMake target; compile it as a standalone source file.

## Safety and ethics

Use this code only in systems you own or are explicitly authorized to analyze. Avoid extending the example with payload execution, process injection, persistence, or evasion behavior outside a controlled lab environment.