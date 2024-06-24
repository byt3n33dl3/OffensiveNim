## OffensiveNimxxx

My experiments in weaponizing [Nim](https://nim-lang.org/) for implant development and general offensive operations.

## Table of Contents

- [OffensiveNim](#offensivenim)
  - [Table of Contents](#table-of-contents)
  - [Why Nim?](#why-nim)
  - [Examples in this repo that work](#examples-in-this-repo-that-work)
  - [Examples that are a WIP](#examples-that-are-a-wip)
  - [Compiling the examples in this repo](#compiling-the-examples-in-this-repo)
    - [Easy Way (Recommended)](#easy-way-recommended)
    - [Hard way (For the bold)](#hard-way-for-the-bold)
  - [Cross Compiling](#cross-compiling)
  - [Interfacing with C/C++](#interfacing-with-cc)
  - [Creating Windows DLLs with an exported `DllMain`](#creating-windows-dlls-with-an-exported-dllmain)
    - [Creating XLLs](#creating-xlls)
  - [Optimizing executables for size](#optimizing-executables-for-size)
  - [Reflectively Loading Nim Executables](#reflectively-loading-nim-executables)
  - [Executable size difference when using the Winim library vs without](#executable-size-difference-when-using-the-winim-library-vs-without)
  - [Opsec Considerations](#opsec-considerations)
  - [Writing Nim without the Nim Runtime](#writing-nim-without-the-nim-runtime)
  - [Converting C code to Nim](#converting-c-code-to-nim)
  - [Language Bridges](#language-bridges)
  - [Debugging](#debugging)
  - [Setting up a dev environment](#setting-up-a-dev-environment)
  - [Pitfalls I found myself falling into](#pitfalls-i-found-myself-falling-into)
  - [Interesting Nim libraries](#interesting-nim-libraries)
  - [Nim for implant dev links](#nim-for-implant-dev-links)
  - [Contributors](#contributors)

## Why Nim?

- Compiles *directly* to C, C++, Objective-C and Javascript.
- Since it doesn't rely on a VM/runtime does not produce what I like to call "T H I C C malwarez" as supposed to other languages (e.g. Golang)
- Python inspired syntax, allows rapid native payload creation & prototyping.
- Has **extremely** mature [FFI](https://nim-lang.org/docs/manual.html#foreign-function-interface) (Foreign Function Interface) capabilities.
- Avoids making you actually write in C/C++ and subsequently avoids introducing a lot of security issues into your software.
- Super easy cross compilation to Windows from *nix/MacOS, only requires you to install the `mingw` toolchain and passing a single flag to the nim compiler.
- The Nim compiler and the generated executables support all major platforms like Windows, Linux, BSD and macOS. Can even compile to Nintendo switch , IOS & Android. See the cross-compilation section in the [Nim compiler usage guide](https://nim-lang.github.io/Nim/nimc.html#crossminuscompilation)
- You could *technically* write your implant and c2 backend both in Nim as you can compile your code directly to Javascript. Even has some [initial support for WebAssembly's](https://forum.nim-lang.org/t/4779) 

## Examples in this repo that work

| File | Description |
| ---  | --- |
| [pop_bin.nim](../master/src/pop_bin.nim) | Call `MessageBox` WinApi *without* using the Winim library |
| [pop_winim_bin.nim](../master/src/pop_winim_bin.nim) | Call `MessageBox` *with* the Winim libary |
| [pop_winim_lib.nim](../master/src/pop_winim_lib.nim) | Example of creating a Windows DLL with an exported `DllMain` |
| [execute_assembly_bin.nim](../master/src/execute_assembly_bin.nim) | Hosts the CLR, reflectively executes .NET assemblies from memory |
| [clr_host_cpp_embed_bin.nim](../master/src/clr_host_cpp_embed_bin.nim) | Hosts the CLR by directly embedding C++ code, executes a .NET assembly from disk |
| [scshell_c_embed_bin.nim](../master/src/scshell_c_embed_bin.nim) | Shows how to quickly weaponize existing C code by embedding [SCShell](https://github.com/Mr-Un1k0d3r/SCShell) (C) directly within Nim |
| [fltmc_bin.nim](../master/src/fltmc_bin.nim) | Enumerates all Minifilter drivers |
| [blockdlls_acg_ppid_spoof_bin.nim](../master/src/blockdlls_acg_ppid_spoof_bin.nim) | Creates a suspended process that spoofs its PPID to explorer.exe, also enables BlockDLLs and ACG |
| [named_pipe_client_bin.nim](../master/src/named_pipe_client_bin.nim) | Named Pipe Client |
| [named_pipe_server_bin.nim](../master/src/named_pipe_server_bin.nim) | Named Pipe Server |
| [embed_rsrc_bin.nim](../master/src/embed_rsrc_bin.nim) | Embeds a resource (zip file) at compile time and extracts contents at runtime |
| [self_delete_bin.nim](../master/src/self_delete_bin.nim) | A way to delete a locked or current running executable on disk. Method discovered by [@jonasLyk](https://twitter.com/jonasLyk/status/1350401461985955840) |
| [encrypt_decrypt_bin.nim](../master/src/encrypt_decrypt_bin.nim) | Encryption/Decryption using AES256 (CTR Mode) using the [Nimcrypto](https://github.com/cheatfate/nimcrypto) library |
| [amsi_patch_bin.nim](../master/src/amsi_patch_bin.nim) | Patches AMSI out of the current process |
| [amsi_providerpatch_bin.nim](../master/src/amsi_providerpatch_bin.nim) | Patches the AMSI Provider DLL (in this case MpOav.dll) to bypass AMSI. Published [here](https://i.blackhat.com/Asia-22/Friday-Materials/AS-22-Korkos-AMSI-and-Bypass.pdf) |
| [etw_patch_bin.nim](../master/src/etw_patch_bin.nim) | Patches ETW out of the current process (Contributed by ) |
| [wmiquery_bin.nim](../master/src/wmiquery_bin.nim) | Queries running processes and installed AVs using using WMI |
| [out_compressed_dll_bin.nim](../master/src/out_compressed_dll_bin.nim) | Compresses, Base-64 encodes and outputs PowerShell code to load a managed dll in memory. Port of the orignal PowerSploit script to Nim. |
| [dynamic_shellcode_local_inject_bin.nim](../master/src/dynamic_shellcode_local_inject_bin.nim) | POC to locally inject shellcode recovered dynamically instead of hardcoding it in an array. | 
| [shellcode_callback_bin.nim](../master/src/shellcode_callback_bin.nim) | Executes shellcode using Callback functions |
| [shellcode_bin.nim](../master/src/shellcode_bin.nim) | Creates a suspended process and injects shellcode with `VirtualAllocEx`/`CreateRemoteThread`. Also demonstrates the usage of compile time definitions to detect arch, os etc..|
| [shellcode_fiber.nim](../master/src/shellcode_fiber.nim) | Shellcode execution via fibers |
| [shellcode_inline_asm_bin.nim](../master/src/shellcode_inline_asm_bin.nim) | Executes shellcode using inline assembly |
| [ssdt_dump.nim](../master/src/ssdt_dump.nim) | Simple SSDT retrieval using runtime function table from exception directory. Technique inspired from [MDSEC](https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/) article |
| [syscalls_bin.nim](../master/src/syscalls_bin.nim) | Shows how to make direct system calls |
| [execute_powershell_bin.nim](../master/src/execute_powershell_bin.nim) | Hosts the CLR & executes PowerShell through an un-managed runspace |
| [passfilter_lib.nim](../master/src/passfilter_lib.nim) | Log password changes to a file by (ab)using a password complexity filter |
| [minidump_bin.nim](../master/src/minidump_bin.nim) | Creates a memory dump of lsass using `MiniDumpWriteDump` |
| [http_request_bin.nim](../master/src/http_request_bin.nim) | Demonstrates a couple of ways of making HTTP requests |
| [execute_sct_bin.nim](../master/src/execute_sct_bin.nim) | `.sct` file Execution via `GetObject()` |
| [scriptcontrol_bin.nim](../master/src/scriptcontrol_bin.nim) | Dynamically execute VBScript and JScript using the `MSScriptControl` COM object |
| [excel_com_bin.nim](../master/src/excel_com_bin.nim) | Injects shellcode using the Excel COM object and Macros |
| [keylogger_bin.nim](../master/src/keylogger_bin.nim) | Keylogger using `SetWindowsHookEx` |
| [memfd_python_interpreter_bin.nim](../master/src/memfd_python_interpreter_bin.nim) | Use `memfd_create` syscall to load a binary into an anonymous file and execute it with `execve` syscall. |
| [uuid_exec_bin.nim](../master/src/uuid_exec_bin.nim) | Plants shellcode from UUID array into heap space and uses `EnumSystemLocalesA` Callback in order to execute the shellcode. |
| [unhookc.nim](../master/src/unhookc.nim) | Unhooks ntdll.dll to evade EDR/AV hooks (embeds the C code template from [ired.team](https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++)) |
| [unhook.nim](../master/src/unhook.nim) | Unhooks ntdll.dll to evade EDR/AV hooks (pure nim implementation) |
| [taskbar_ewmi_bin.nim](../master/src/taskbar_ewmi_bin.nim) | Uses Extra Window Memory Injection via Running Application property of TaskBar in order to execute the shellcode. |
| [fork_dump_bin.nim](../master/src/fork_dump_bin.nim) | (ab)uses Window's implementation of `fork()` and acquires a handle to a remote process using the PROCESS_CREATE_PROCESS access right. It then attempts to dump the forked processes memory using `MiniDumpWriteDump()` |
| [ldap_query_bin.nim](../master/src/ldap_query_bin.nim) | Perform LDAP queries via COM by using ADO's ADSI provider |
| [sandbox_process_bin.nim](../master/src/sandbox_process_bin.nim) | This sandboxes a process by setting it's integrity level to Untrusted and strips important tokens. This can be used to "silently disable" a PPL process (e.g. AV/EDR) |
| [list_remote_shares.nim](../master/src/list_remote_shares.nim) | Use NetShareEnum to list the share accessible by the current user |
| [chrome_dump_bin.nim](../master/src/chrome_dump_bin.nim) | Read and decrypt cookies from Chrome's sqlite database|
| [suspended_thread_injection.nim](../master/src/suspended_thread_injection.nim) | Shellcode execution via suspended thread injection |
| [dns_exfiltrate.nim](../master/src/dns_exfiltrate.nim) | Simple DNS exfiltration via TXT record queries |
| [rsrc_section_shellcode.nim](../master/src/rsrc_section_shellcode.nim) | Execute shellcode embedded in the .rsrc section of the binary |
| [token_steal_cmd.nim](../master/src/token_steal_cmd.nim) | Steal a token/impersonate and then run a command | 
| [anti_analysis_isdebuggerpresent.nim](../master/src/anti_analysis_isdebuggerpresent.nim) | Simple anti-analysis that checks for a debugger | 
| [sandbox_domain_check.nim](../master/src/sandbox_domain_check.nim) | Simple sandbox evasion technique, that checks if computer is connected to domain or not |
| [Hook.nim](../master/src/Hook.nim) | Offensive Hooking example for MessageBoxA | 
| [anti_debug.nim](../master/src/anti_debug.nim) | Showcasing two anti debugging techniques | 
| [anti_debug_via_tls.nim](../master/src/anti_debug_via_tls.nim) | Anti-debugging vis TLS |
| [local_pe_execution.nim](../master/src/local_pe_execution.nim) | Execute exe and dll files in memory | 
| [stack_string_allocation.nim](../master/src/stack_string_allocation.nim) | Allocate c and wide strings on the stack using arrays | 
| [hardware_breakpoints.nim](../master/src/hardware_breakpoints.nim) | Hook functions using hardware breakpoints | 

Thanks to bytlebleeder
