# Sektor7-MDI-Final
The final project of the Sektor7 Malware Development Intermediate (MDI) course consists of three parts:
- **VCpersist** that is to be run by any kind of persistence mechanism to reflectively inject a 32-bit DLL **VCmigrate.dll** into a 32-bit Notepad (C:\Windows\SysWOW64\notepad.exe)
- **VCmigrate** that allocates memory and reflectively injects a 64-bit DLL (via sRDI) **VCsniff.dll** into a VeraCrypt process with the help of Heaven's Gate to get to the Long (X64) Mode
- **VCsniff** that upon injection into the VeraCrypt process performs IAT Hooking to hook WideCharToMultiByte WinAPI and store all snatched passwords in a file

## VCpersist
There is nothing special about this one. Takes the DLL either from a file or from the resource section and reflectively injects it into a remote 32-bit Notepad process using [ImprovedReflectiveDLLInjection](https://github.com/dismantl/ImprovedReflectiveDLLInjection). For demonstration purposes, it also uses indirect syscalls ([SysWhispers3](https://github.com/klezVirus/SysWhispers3)) to perform process enumeration with NtQuerySystemInformation.

## VCmigrate
After being reflectively loaded into a 32-bit Notepad process, it will use Heaven's Gate to indirectly get into the Long Mode in order to call RtlCreateUserThread and create a new thread in the remote, target VeraCrypt process. This new thread will run shellcode generated with [sRDI](https://github.com/monoxgas/sRDI/) to reflectively load another DLL VCsniff.dll into the process.

This is where the biggest challenge of the project was. I used my own Windows VM with modern exploitation defenses instead of the machine provided by the course. VeraCrypt has a Mitigation Policy defined that, among other things, prohibits dynamically loaded code from executing, also known as [Arbitrary Code Guard](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference#arbitrary-code-guard). In short, ACG prohibits execution of code that has been dynamically loaded from within the process by preventing memory pages from being marked as executable (with VirtualProtect, for instance). This also includes memory pages that had already been allocated and executable (RX), but were changed to RW in order to write the code.

As a result, reflective loading of the DLL by the bootstrap shellcode provided by sRDI failed, as the memory page where the DLL was loaded could not be made executable. To circumvent this, I executed Heaven's Gate twice - first to create the thread with RtlCreateUser Thread and second to change the memory protections remotely. ACG prohibits execution of code that was locally allocated and loaded, but it doesn't stop remote process from doing it. The Assembly (shell)code for running NtProtectVirtualMemory can be found in the repo, as well.

VCsniff.dll uses a base address of 0x00000001`80000000 as its preferred address to load itself in memory. It's therefore possible to use NtProtectVirtualMemory to remotely make this memory page executable before execution is transferred to the VCsniff DLL. To make it even more reliable, a small delay was introduced in the sRDI shellcode before DLL imports.

## VCsniff
VCsniff uses IAT Hooking for the same reason - ACG doesn't allow me to overwrite the first few bytes of a WinAPI to add a trampoline code necessary for hooking. It could have, however, been circumvented in a similar way by relying on the VCmigrate DLL to remotely inject the trampoline code and make the memory page executable.

It hooks WideCharToMultiByte WinAPI and stores the passwords it snatches in a file. It then calls the original WinAPI to make VeraCrypt behave properly and continue execution.

The sRDI shellcode was generated with this [PR](https://github.com/monoxgas/sRDI/pull/36) because there is a bug in the original sRDI code that makes the delays too big.
`python ConvertToShellcode.py -i -d 1 -f HookVera -of string VCsniff.dll`

## Remarks
The code is definitely ugly, but it's just a course project. :)
