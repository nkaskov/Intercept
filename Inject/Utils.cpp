#include "stdafx.h"

#include "Utils.h"

#include "psapi.h"

//#pragma comment(lib, "psapi.lib")

DWORD GetProcessName(DWORD processId, LPWSTR processName, DWORD nSize)
{
	HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,	processId);
	if (handle)
	{
		DWORD ret = GetModuleBaseName(handle, NULL, processName, nSize);
		CloseHandle(handle);

		return ret;
	}
	return 0;
}