// Copyright (c) 2015, Dan Staples

//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "ReflectiveLoader.h"
//===============================================================================================//

typedef BOOL(*EXPORTFUNC)(LPVOID, DWORD);

// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HMODULE hAppInstance = NULL;

// This is our position independent reflective DLL loader/injector
DLLEXPORT VOID WINAPI ReflectiveLoader(LPVOID lpParameter, LPVOID lpLibraryAddress, DWORD dwFunctionHash, LPVOID lpUserData, DWORD nUserdataLen)
{
	// the functions we need
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	EXITTHREAD pExitThread = NULL;
	EXITTHREAD pRtlExitUserThread = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

	USHORT usCounter;

	// the initial location of this image in memory
	ULONG_PTR uiLibraryAddress;
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;

	// variables for processing the kernels export table
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;
	ULONG_PTR uiNameOrdinals;
	DWORD dwHashValue;
	DWORD dwNumberOfNames;

	// variables for loading this image
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;

	// exit code for current thread
	DWORD dwExitCode = 1;

	uiLibraryAddress = (ULONG_PTR)lpLibraryAddress;

	// STEP 1: process the kernels exports for the functions our loader needs...

	// get the Process Enviroment Block
//#define WIN_X64
#ifdef WIN_X64
	uiBaseAddress = __readgsqword(0x60);
#else
#ifdef WIN_X86
	uiBaseAddress = __readfsdword(0x30);
#else WIN_ARM
	uiBaseAddress = *(DWORD*)((BYTE*)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#endif
#endif

	// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;

	// get the first entry of the InMemoryOrder module list
	uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;
	while (uiValueA)
	{
		// get pointer to current modules name (unicode string)
		uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;
		// set bCounter to the length for the loop
		usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
		// clear uiValueC which will store the hash of the module name
		uiValueC = 0;

		// compute the hash of the module name...
		do
		{
			uiValueC = ror((DWORD)uiValueC);
			// normalize to uppercase if the madule name is in lowercase
			if (*((BYTE*)uiValueB) >= 'a')
				uiValueC += *((BYTE*)uiValueB) - 0x20;
			else
				uiValueC += *((BYTE*)uiValueB);
			uiValueB++;
		} while (--usCounter);

		// compare the hash with that of kernel32.dll
		if ((DWORD)uiValueC == KERNEL32DLL_HASH)
		{
			// get this modules base address
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

			// get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			// get the VA for the array of name pointers
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

			// get the VA for the array of name ordinals
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

			usCounter = 4;

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				dwHashValue = hash((char*)(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				if (dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH || dwHashValue == VIRTUALALLOC_HASH || dwHashValue == EXITTHREAD_HSAH)
				{
					// get the VA for the array of addresses
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if (dwHashValue == LOADLIBRARYA_HASH)
						pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == GETPROCADDRESS_HASH)
						pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == VIRTUALALLOC_HASH)
						pVirtualAlloc = (VIRTUALALLOC)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == EXITTHREAD_HSAH)
						pExitThread = (EXITTHREAD)(uiBaseAddress + DEREF_32(uiAddressArray));

					// decrement our counter
					usCounter--;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}
		else if ((DWORD)uiValueC == NTDLLDLL_HASH)
		{
			// get this modules base address
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

			// get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			// get the VA for the array of name pointers
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

			// get the VA for the array of name ordinals
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

			// get total number of named exports
			dwNumberOfNames = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

			usCounter = 2;

			// loop while we still have imports to find
			while (usCounter > 0 && dwNumberOfNames > 0)
			{
				// compute the hash values for this function name
				dwHashValue = hash((char*)(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH || dwHashValue == RTLEXITUSERTHREAD_HASH)
				{
					// get the VA for the array of addresses
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
						pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == RTLEXITUSERTHREAD_HASH)
						pRtlExitUserThread = (EXITTHREAD)(uiBaseAddress + DEREF_32(uiAddressArray));

					// decrement our counter
					usCounter--;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);

				// decrement our # of names counter
				dwNumberOfNames--;
			}
		}

		// we stop searching when we have found everything we need.
		if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pExitThread && pNtFlushInstructionCache)
			break;

		// get the next entry
		uiValueA = DEREF(uiValueA);
	}

	// STEP 2: load our image into a new permanent location in memory...

	// get the VA of the NT Header for the PE to be loaded
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// we must now copy over the headers
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;

	while (uiValueA--)
		*(BYTE*)uiValueC++ = *(BYTE*)uiValueB++;

	// STEP 3: load in all of our sections...

	// uiValueA = the VA of the first section
	uiValueA = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

	// itterate through all sections, loading them into memory.
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while (uiValueE--)
	{
		// uiValueB is the VA for this section
		uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

		// uiValueC if the VA for this sections data
		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

		// copy the section over
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

		while (uiValueD--)
			*(BYTE*)uiValueB++ = *(BYTE*)uiValueC++;

		// get the VA of the next section
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}

	// STEP 4: process our images import table...

	// uiValueB = the address of the import directory
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

	// itterate through all imports
	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		uiLibraryAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREF(uiValueA))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

				// get the VA for the array of addresses
				uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
			}
			else
			{
				// get the VA of this functions import by name struct
				uiValueB = (uiBaseAddress + DEREF(uiValueA));

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
			}
			// get the next imported function
			uiValueA += sizeof(ULONG_PTR);
			if (uiValueD)
				uiValueD += sizeof(ULONG_PTR);
		}

		// get the next import
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	// STEP 5: process all of our images relocations...

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// check if their are any relocations present
	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

		// and we itterate through all entries...
		while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)
		{
			// uiValueA = the VA for this relocation block
			uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while (uiValueB--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
#ifdef WIN_ARM
				// Note: On ARM, the compiler optimization /O2 seems to introduce an off by one issue, possibly a code gen bug. Using /O1 instead avoids this problem.
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_ARM_MOV32T)
				{
					register DWORD dwInstruction;
					register DWORD dwAddress;
					register WORD wImm;
					// get the MOV.T instructions DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word)
					dwInstruction = *(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD));
					// flip the words to get the instruction as expected
					dwInstruction = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
					// sanity chack we are processing a MOV instruction...
					if ((dwInstruction & ARM_MOV_MASK) == ARM_MOVT)
					{
						// pull out the encoded 16bit value (the high portion of the address-to-relocate)
						wImm = (WORD)(dwInstruction & 0x000000FF);
						wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
						wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
						wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
						// apply the relocation to the target address
						dwAddress = ((WORD)HIWORD(uiLibraryAddress) + wImm) & 0xFFFF;
						// now create a new instruction with the same opcode and register param.
						dwInstruction = (DWORD)(dwInstruction & ARM_MOV_MASK2);
						// patch in the relocated address...
						dwInstruction |= (DWORD)(dwAddress & 0x00FF);
						dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
						dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
						dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
						// now flip the instructions words and patch back into the code...
						*(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD)) = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
					}
				}
#endif
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

				// get the next entry in the current relocation block
				uiValueD += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}

	// STEP 6: call our images entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);

	do
	{
		PIMAGE_DATA_DIRECTORY directory = &((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (directory->Size == 0)
			break;

		PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(uiBaseAddress + directory->VirtualAddress);
		if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0)
			break;

		// search function name in list of exported names
		int idx = -1;
		DWORD* nameRef = (DWORD*)(uiBaseAddress + exports->AddressOfNames);
		WORD* ordinal = (WORD*)(uiBaseAddress + exports->AddressOfNameOrdinals);
		for (DWORD i = 0; i < exports->NumberOfNames; i++, nameRef++, ordinal++) {
			if (hash((char*)(uiBaseAddress + (*nameRef))) == dwFunctionHash) {
				idx = *ordinal;
				break;
			}
		}
		if (idx == -1)
			break;

		// AddressOfFunctions contains the RVAs to the "real" functions
		EXPORTFUNC f = (EXPORTFUNC)(uiBaseAddress + (*(DWORD*)(uiBaseAddress + exports->AddressOfFunctions + (idx * 4))));
		if (!f(lpUserData, nUserdataLen))
			break;

		dwExitCode = 0;
	} while (0);

	// We're done, exit thread
	if (pRtlExitUserThread)
		pRtlExitUserThread(dwExitCode);
	else
		pExitThread(dwExitCode);
}
