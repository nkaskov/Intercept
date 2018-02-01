#include "stdafx.h"

#include <Shellapi.h>
//#pragma comment(lib, "Shell32.lib")

#include "Function.h"
#include "DllGlobal.h"

#include "MinHook.h"

HANDLE internal_server_handle;
DWORD internal_server_id;

/*#if defined _M_X64
#pragma comment(lib, "libMinHook-x64-v141-mt.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86-v141-mt.lib")
#endif*/


#define ENABLEHOOK(func) \
if (MH_CreateHook(&func, &Detour ## func, \
	reinterpret_cast<LPVOID*>(&fp ## func)) != MH_OK) \
{ \
	return; \
} \
if (MH_EnableHook(&func) != MH_OK) \
{ \
	return; \
}



void CreateConsole(void)
{
	if (AllocConsole()) {
		freopen("CONOUT$", "w", stdout);
		SetConsoleTitle(L"Debug Console");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		_tprintf(TEXT("DLL loaded at %X\n"), GetModuleHandle(NULL));
	}
}

void SetupHook()
{
	// Initialize MinHook.
	if (MH_Initialize() != MH_OK)
	{
		return;
	}
	
	ENABLEHOOK(OpenProcess);
	ENABLEHOOK(CreateProcessA);
	ENABLEHOOK(CreateProcessW);
	ENABLEHOOK(CreateRemoteThread);
	
	ENABLEHOOK(WriteFile);
	ENABLEHOOK(ReadFile);
	ENABLEHOOK(OpenFile);
	ENABLEHOOK(CreateFileA);
	ENABLEHOOK(CreateFileW);
	ENABLEHOOK(DeleteFileA);
	ENABLEHOOK(DeleteFileW);
	
	ENABLEHOOK(RegCreateKeyExA);
	ENABLEHOOK(RegCreateKeyExW);
	ENABLEHOOK(RegCreateKeyA);
	ENABLEHOOK(RegCreateKeyW);
	ENABLEHOOK(RegSetValueExA);
	ENABLEHOOK(RegSetValueExW);
	ENABLEHOOK(RegOpenKeyExA);
	ENABLEHOOK(RegOpenKeyExW);
	ENABLEHOOK(RegQueryValueExA);
	ENABLEHOOK(RegQueryValueExW);
	
	ENABLEHOOK(LoadLibraryA);
	ENABLEHOOK(LoadLibraryW);
	
	ENABLEHOOK(ShellExecuteExA);
	ENABLEHOOK(ShellExecuteExW);

	ENABLEHOOK(SetCurrentDirectoryA);
	ENABLEHOOK(SetCurrentDirectoryW);

	ENABLEHOOK(OutputDebugStringA);
	ENABLEHOOK(OutputDebugStringW);

	ENABLEHOOK(MoveFileExA);
	ENABLEHOOK(MoveFileExW);

	return;
}

extern BOOL block_mutex_is_up;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD nReason, VOID* pvReserved)
{
	if (nReason == DLL_PROCESS_ATTACH)
	{
		CreateConsole();

		block_mutex_is_up = TRUE;

		processId = GetCurrentProcessId();
		GetModuleFileName(NULL, moduleName, MAX_PATH);
		PathStripPath(moduleName);


		_tprintf(TEXT("Loaded from %s with ProcessId %d\n"), moduleName, processId);
		fflush(stdout);


		HMODULE ntdll = LoadLibrary(L"ntdll.dll");
		NtQueryKey = reinterpret_cast<NtQueryKeyType>(::GetProcAddress(ntdll, "NtQueryKey"));

		SetupHook();

		internal_server_handle = CreateThread(
			NULL,              // no security attribute 
			0,                 // default stack size 
			SendMessageFromInternalServer,    // thread proc
			NULL,    // thread parameter 
			0,                 // not suspended 
			&internal_server_id);     // returns thread ID

	}

	return TRUE;
}

