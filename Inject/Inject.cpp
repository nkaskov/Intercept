#include "stdafx.h"
#include <atlstr.h>
#include <atlpath.h>

#include <tlhelp32.h>
#include <time.h>
#include <thread>

#include "Queue.h"
#include "Mutants.h"
#include "utlist.h"
#include "Global.h"

#include "Network.h"
#include "Dump.h"
#include "pcap.h"

using namespace ATL::ATLPath;

int inject(DWORD nProcessIdentifier, WCHAR *libraryPath)
{
	WCHAR pszPath[MAX_PATH];
	//ATLVERIFY(GetModuleFileName(NULL, pszPath, _countof(pszPath)));
	//ATLVERIFY(RemoveFileSpec(pszPath));
	wcscpy(pszPath, libraryPath);
	//ATLVERIFY(Combine(pszPath, dllPath, libraryName));
	//_tprintf(_T("Dll library path: %s\n"), pszPath);
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS|PROCESS_VM_OPERATION|PROCESS_QUERY_INFORMATION, FALSE, nProcessIdentifier);
	if (!processHandle)
	{
		_tprintf(_T("OpenProcess error: 0x%08X\n"), GetLastError());
		CloseHandle(processHandle);
		return 1;
	}

	CHandle Process;
	Process.Attach(processHandle);
	ATLENSURE_THROW(Process, AtlHresultFromLastError());
	VOID* pvProcessPath = VirtualAllocEx(Process, NULL, sizeof pszPath, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pvProcessPath) {
		printf("VirtualAllocEx failed. GLE = %d\n", GetLastError());
		fflush(stdout);
		return 1;
	}
	_tprintf(_T("pvProcessPath 0x%p\n"), pvProcessPath);
	
	ATLENSURE_THROW(pvProcessPath, AtlHresultFromLastError());
	_ATLTRY
	{
	ATLENSURE_THROW(WriteProcessMemory(Process, pvProcessPath, pszPath, sizeof pszPath, NULL), AtlHresultFromLastError());
	//_tprintf(_T("pvProcessPath 0x%p\n"), pvProcessPath);
#if !defined(_UNICODE)
#error Assumed is Unicode build
#endif
	VOID* pvLoadLibraryAddress = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "LoadLibraryW");
	if (!pvLoadLibraryAddress) {
		printf("GetProcAddress failed. GLE = %u\n", GetLastError());
		fflush(stdout);
		return 1;
	}
	ATLENSURE_THROW(pvLoadLibraryAddress, AtlHresultFromLastError());

	CHandle Thread;
	DWORD nThreadIdentifier;
	HANDLE threadHandle = CreateRemoteThread(Process, NULL, NULL, (LPTHREAD_START_ROUTINE)pvLoadLibraryAddress, pvProcessPath, 0, &nThreadIdentifier);
	if (!threadHandle)
	{
		_tprintf(_T("CreateRemoteThread failed: 0x%08X\n"), GetLastError());
		CloseHandle(threadHandle);
		CloseHandle(processHandle);
		return 1;
	}
	Thread.Attach(threadHandle);
	ATLENSURE_THROW(Thread, AtlHresultFromLastError());
	_tprintf(_T("nThreadIdentifier %d\n"), nThreadIdentifier);
	const DWORD nWaitResult = WaitForSingleObject(Thread, INFINITE);
	_tprintf(_T("nWaitResult 0x%x\n"), nWaitResult);

	CloseHandle(threadHandle);
	CloseHandle(processHandle);
	}
		_ATLCATCHALL()
	{
		ATLVERIFY(VirtualFreeEx(Process, pvProcessPath, 0, MEM_RELEASE));
		_ATLRETHROW;
	}
	ATLVERIFY(VirtualFreeEx(Process, pvProcessPath, 0, MEM_RELEASE));

	return 0;
}

#define WINDOWS_TICK 10000000
#define SEC_TO_UNIX_EPOCH 11644473600LL

ULONGLONG getProcessTime(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);

	FILETIME creationTime, exitTime, kernelTime, userTime;
	
	if (processHandle && GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime))
	{
		CloseHandle(processHandle);
		return ((((ULONGLONG)creationTime.dwHighDateTime) << 32) + (ULONGLONG)creationTime.dwLowDateTime) / WINDOWS_TICK - SEC_TO_UNIX_EPOCH;
	}
	
	CloseHandle(processHandle);
	return 0;
}


BOOL isDirectInjection(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
	BOOL directInjection = FALSE;
	BOOL wow64;

	if (processHandle && IsWow64Process(processHandle, &wow64))
	{
#if defined _M_X64
		if (!wow64)
#elif defined _M_IX86
		if (wow64)
#endif
		{
			directInjection = TRUE;
		}
	}
	CloseHandle(processHandle);

	return directInjection;
}

#define RUNNING_TIME 1

void injectDlls(void)
{
	struct processInfo *item;
	struct processInfo *tmp;

	while (TRUE) {

		DL_FOREACH(globalList, item)
		{
			item->running = FALSE;
		}

		// Create toolhelp snapshot.
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 process;
		ZeroMemory(&process, sizeof(process));
		process.dwSize = sizeof(process);
		// Walkthrough all processes.
		if (Process32First(snapshot, &process))
		{

			do
			{
				DWORD pid = process.th32ProcessID;
				ULONGLONG ts = time(NULL);
				
				DL_FOREACH_SAFE(globalList, item, tmp)
				{
					if (item->persistent && wcscmp(process.szExeFile, item->processName) == 0)
					{
						BOOL found = FALSE;
						for (unsigned int j = 0; j < item->pidCount; ++j)
						{
							if (pid == item->pidList[j])
							{
								found = TRUE;
								break;
							}
						}
						item->running = TRUE;
						if (found || ts - getProcessTime(pid) < item->delay)
						{
							break;
						}
						item->pidList[item->pidCount++] = pid;
					}
					else if (!item->persistent && item->pidList[0] == pid)
					{
						item->running = TRUE;
						if (ts - getProcessTime(pid) < item->delay)
						{
							break;
						}
						DL_DELETE(globalList, item);
						DL_APPEND(trashList, item);
					}
					else
					{
						continue;
					}

					if (!item->hook)
					{
						continue;
					}

					if (isDirectInjection(pid))
					{
#if defined _M_X64
						int ret = inject(pid, dllPathX64);
#elif defined _M_IX86
						int ret = inject(pid, dllPathX86);
#endif
						if (ret)
						{
							wprintf(L"Can't direct inject DLL in process with ProcessId %d: unknown error\n", pid);
						}
						else
						{
							wprintf(L"Direct Injected DLL in process with ProcessId %d\n", pid);
						}
					}
					else
					{
						PROCESS_INFORMATION processInformation = { 0 };
						STARTUPINFO startupInfo = { 0 };
						startupInfo.cb = sizeof(startupInfo);

						WCHAR cmdLine[2 * MAX_PATH + 16];
#if defined _M_X64
						wsprintf(cmdLine, L"\"%s\" %d \"%s\"", interlayerPath, pid, dllPathX86);
#elif defined _M_IX86
						wsprintf(cmdLine, L"\"%s\" %d \"%s\"", interlayerPath, pid, dllPathX64);
#endif
						//wprintf(L"cmd: %s\n", cmdLine);

						BOOL result = CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, 0/* | CREATE_NO_WINDOW*/, NULL, NULL, &startupInfo, &processInformation);
						if (result)
						{
							WaitForSingleObject(processInformation.hProcess, 10000);

							CloseHandle(processInformation.hProcess);
							CloseHandle(processInformation.hThread);

							wprintf(L"Injected DLL in process with ProcessId %d\n", pid);
						}
						else
						{
							wprintf(L"Can't inject DLL in process with ProcessId %d: unknown error\n", pid);
						}
					}

					break;
				}
			} while (Process32Next(snapshot, &process));
		}
		CloseHandle(snapshot);

		DL_FOREACH_SAFE(globalList, item, tmp)
		{
			if (!item->running)
			{
				if (item->persistent)
				{
					item->pidCount = 0;
				}
				else
				{
					_tprintf(TEXT("Process %s with ProcessId %d isn't running: removed\n"), item->processName, item->pidList[0]);
					DL_DELETE(globalList, item);
					DL_APPEND(trashList, item);
				}
			}

		}

		Sleep(5);
	}
}


int _tmain(int argc, _TCHAR* argv[]){
//int Inject(){
	if (initGlobal()){
		printf("Can not parse config..Bye\n");
		return 1;
	}
	
	initNetwork();

	Sleep(1000);

	initDump();

	std::thread *monitorThread;
	startMonitorQueue(&monitorThread);

	std::thread *mutantsThread;
	startMutantsMonitor(&mutantsThread);

	injectDlls();

	

	return 0;
}