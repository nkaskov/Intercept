#include "stdafx.h"

#include "Function.h"
#include "DllGlobal.h"

#define MAX_PIPES_FOR_SEGMENT 10
#define BUFSIZE 0
#define base_pipe_name L"\\\\.\\pipe\\my_pipe"
HANDLE pipe = NULL;
#define MAX_ATTEMPTS_TO_CONNECT_TO_ONE_SEGMENT 20
#define MAX_ATTEMPTS_TO_SEND_TO_ONE_SERVER 100
#define BIG_CMD_SIZE 2000
DWORD attempts_to_connect = 0;
DWORD attempts_to_send = 0;
DWORD segment_number = 0;

PTCHAR big_cmd = NULL;

BOOL block_mutex_is_up;

void SendMessageToMonitorServer(PTCHAR cmd);

DWORD WINAPI SendMessageFromInternalServer(LPVOID lpvParam) {
	
	block_mutex_is_up = TRUE;

	if (block_mutex_is_up) {
		big_cmd = (PTCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BIG_CMD_SIZE * sizeof(TCHAR));
	}
	else {
		printf("Block mutex is not up!\n");
		fflush(stdout);
	}
	block_mutex_is_up = FALSE;

	while (TRUE) {
		Sleep(100);
		while (block_mutex_is_up) { Sleep(10); }

		block_mutex_is_up = TRUE;
		if (block_mutex_is_up){
			if (wcslen(big_cmd)) {
				SendMessageToMonitorServer(big_cmd);
				big_cmd[0] = '\0';
			}
		}
		else {
			printf("Block mutex is down\n");
			fflush(stdout);
		}
		block_mutex_is_up = FALSE;
	}
}

DWORD CreatePipeMonitorInternal() {
	//static DWORD wrong_attempt_counter = 0;
	attempts_to_connect++;
	if (attempts_to_connect >= MAX_ATTEMPTS_TO_CONNECT_TO_ONE_SEGMENT) {
		attempts_to_connect = 0;
		_tprintf(TEXT("Server is unavailable to long.\n"));
		//return 0;
		segment_number += 1;
	}

	_tprintf(TEXT("Attempts count: %d.\n"), attempts_to_connect);
	fflush(stdout);
	PWCHAR current_pipe_name;
	while (!(current_pipe_name = (PWCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 128 * sizeof(WCHAR))));

	for (DWORD current_pipe_number = segment_number * MAX_PIPES_FOR_SEGMENT; current_pipe_number < (segment_number + 1) * MAX_PIPES_FOR_SEGMENT; current_pipe_number++) {
		wsprintf(current_pipe_name, L"\\\\.\\pipe\\my_pipe_%d", current_pipe_number);
		pipe = CreateNamedPipe(
			current_pipe_name, // name of the pipe
			PIPE_ACCESS_OUTBOUND, // 1-way pipe -- send only
			PIPE_TYPE_BYTE | PIPE_NOWAIT, // send data as a byte stream
			PIPE_UNLIMITED_INSTANCES,
			BUFSIZE,
			BUFSIZE,
			0, // use default wait time
			NULL // use default security attributes
		);

		if (pipe == NULL || pipe == INVALID_HANDLE_VALUE) {
			_tprintf(TEXT("Failed to create outbound pipe instance. GLE = %d.\n"), GetLastError());
			fflush(stdout);
			continue;
		}
		_tprintf(TEXT("Try connect to %s.\n"), current_pipe_name);
		fflush(stdout);
		Sleep(50);
		DWORD numBytesWritten = 0, error = 0;
		BOOL result = WriteFile(
			pipe, // handle to our outbound pipe
			L"CONNECT", // data to send
			7 * sizeof(wchar_t), // length of data to send (bytes)
			&numBytesWritten, // will store actual amount of data sent
			NULL // not using overlapped IO
		);

		if (result) {
			_tprintf(TEXT("Connected to pipe %s.\n"), current_pipe_name);
			segment_number = 0;
			attempts_to_connect = 0;
			fflush(stdout);
			return 0;
		}
		else {
			error = GetLastError();
			_tprintf(TEXT("Failed to send data. GLE = %d.\n"), error);
			fflush(stdout);
			if (error == ERROR_PIPE_LISTENING) {
				DisconnectNamedPipe(pipe);
				CloseHandle(pipe);
				continue;
			}
			else {
				DisconnectNamedPipe(pipe);
				CloseHandle(pipe);
				continue;
			}
		}
	}

	Sleep(50);
	CreatePipeMonitorInternal();
	return 1;
}

void SendMessageToMonitorServer(PTCHAR cmd) {

	if (!cmd) {
		_tprintf(TEXT("Waste message.\n"));
		return;
	}
	attempts_to_send++;
	if (attempts_to_send > MAX_ATTEMPTS_TO_SEND_TO_ONE_SERVER) {
		_tprintf(TEXT("Send Message: %s: "), cmd);
		_tprintf(TEXT("Can not send message %s. No Attempts more.\n"), cmd);
		attempts_to_send = 0;
		//CreatePipeMonitorInternal();
		//SendMessageToMonitorServer(cmd);
		return;
	}

	_tprintf(TEXT("Att %d. Send Message: %s \n"), attempts_to_send, cmd);
	DWORD error = 0;
	DWORD numBytesWritten = 0;

	unsigned long long sizeof_wchar_t = sizeof(wchar_t);
	size_t cmd_len = wcslen(cmd);

	BOOL result = WriteFile(
		pipe, // handle to our outbound pipe
		cmd, // data to send
		cmd_len * sizeof_wchar_t, // length of data to send (bytes)
		&numBytesWritten, // will store actual amount of data sent
		NULL // not using overlapped IO
	);

	if (result) {
		//_tprintf(TEXT("Number of bytes sent: %d.\n"), numBytesWritten);
		fflush(stdout);
		if (!numBytesWritten) {
			SendMessageToMonitorServer(cmd);
		}
		else {
			_tprintf(TEXT("Send Message: %s \n"), cmd);
			attempts_to_send = 0;
			return;
		}
	}
	else {
		error = GetLastError();
		_tprintf(TEXT("Failed to send data. GLE = %d.\n"), error);
		fflush(stdout);
		Sleep(50);
		CreatePipeMonitorInternal();
		SendMessageToMonitorServer(cmd);
	}
}

void SendMessageToInternalServer(PTCHAR cmd) {
	if (!cmd) {
		_tprintf(TEXT("Waste message to internal server.\n"));
		return;
	}

	while (block_mutex_is_up || (_tcslen(cmd) + _tcslen(big_cmd) + 2 > BIG_CMD_SIZE)) { Sleep(100); }

	block_mutex_is_up = TRUE;
	if (block_mutex_is_up) {
		_tcscat(big_cmd, cmd);
		_tcscat(big_cmd, TEXT("\n"));
	}
	else {
		printf("Block is wrong down\n");
		fflush(stdout);
	}
	block_mutex_is_up = FALSE;
}


//---------------------ShellExecuteEx---------------------


SHELLEXECUTEEXW fpShellExecuteExW = NULL;

BOOL __stdcall DetourShellExecuteExW(SHELLEXECUTEINFOW *pExecInfo)
{
	BOOL ret = fpShellExecuteExW(pExecInfo);
	DWORD err = GetLastError();

	DWORD pid = GetProcessId(pExecInfo->hProcess);
	//wprintf(L"ShellExecuteEx %s %s %s %s %s ProcessId %d\n", pExecInfo->lpVerb, pExecInfo->lpFile, pExecInfo->lpParameters, pExecInfo->lpDirectory, pExecInfo->lpClass, pid);
	//wprintf(L"ShellExecuteEx\n");
	try {
		if (pid)
		{
			WCHAR cmd[16];
			wsprintf(cmd, L"p|%d", pid);
			//SendMessageToMonitorServer(cmd);
			SendMessageToInternalServer(cmd);
		}

		size_t argsLen = 2;
		argsLen += pExecInfo->lpVerb == NULL ? 0 : wcslen(pExecInfo->lpVerb);
		argsLen += pExecInfo->lpFile == NULL ? 0 : wcslen(pExecInfo->lpFile);
		argsLen += pExecInfo->lpParameters == NULL ? 0 : wcslen(pExecInfo->lpParameters);

		PWCHAR args = (PWCHAR)malloc((argsLen + 16) * sizeof(WCHAR));
		wsprintf(args, L"%s*%s*%s*%d", pExecInfo->lpVerb == NULL ? L"" : pExecInfo->lpVerb, pExecInfo->lpFile == NULL ? L"" : pExecInfo->lpFile, pExecInfo->lpParameters == NULL ? L"" : pExecInfo->lpParameters, pid);

		PWCHAR cmd = (PWCHAR)malloc((wcslen(moduleName) + argsLen + 64) * sizeof(WCHAR));
		wsprintf(cmd, L"%s|%d|ShellExecuteEx|%s|%d|%d", moduleName, processId, args, ret == TRUE, err);
		if (args) {
			free(args);
			args = NULL;
		}
		//SendMessageToMonitorServer(cmd);
		SendMessageToInternalServer(cmd);
		
		if (cmd) {
			free(cmd);
			cmd = NULL;
		}
	}
	catch (...) {
	}
	return ret;
}


SHELLEXECUTEEXA fpShellExecuteExA = NULL;

BOOL __stdcall DetourShellExecuteExA(SHELLEXECUTEINFOA *pExecInfo)
{
	BOOL ret = fpShellExecuteExA(pExecInfo);

	DWORD pid = GetProcessId(pExecInfo->hProcess);
	//printf("ShellExecuteEx %s %s %s %s %s ProcessId %d\n", pExecInfo->lpVerb, pExecInfo->lpFile, pExecInfo->lpParameters, pExecInfo->lpDirectory, pExecInfo->lpClass, pid);
	//printf("ShellExecuteEx\n");

	if (pid)
	{
		WCHAR cmd[16];
		wsprintf(cmd, L"p|%d", pid);
		//SendMessageToMonitorServer(cmd);
		SendMessageToInternalServer(cmd);
	}
	return ret;
}


//---------------------OpenProcess---------------------


OPENPROCESS fpOpenProcess = NULL;

HANDLE WINAPI DetourOpenProcess(DWORD dwDesiredAccess,
								BOOL bInheritHandle,
								DWORD dwProcessId)
{
	//wprintf(L"OpenProcess %d\n", dwProcessId);
	//wprintf(L"OpenProcess\n");

	HANDLE ret = fpOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);

	return ret;
}


//---------------------CreateProcess---------------------


CREATEPROCESSW fpCreateProcessW = NULL;

BOOL WINAPI DetourCreateProcessW(LPCWSTR lpApplicationName,
									LPWSTR lpCommandLine,
									LPSECURITY_ATTRIBUTES lpProcessAttributes,
									LPSECURITY_ATTRIBUTES lpThreadAttributes,
									BOOL bInheritHandles,
									DWORD dwCreationFlags,
									LPVOID lpEnvironment,
									LPCWSTR lpCurrentDirectory,
									LPSTARTUPINFO lpStartupInfo,
									LPPROCESS_INFORMATION lpProcessInformation)
{

	BOOL ret = fpCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	DWORD err = GetLastError();
	if (ret)
	{
		//wprintf(L"CreateProcessW %s %s %s ProcessId %d\n", lpApplicationName, lpCommandLine, lpCurrentDirectory, lpProcessInformation->dwProcessId);
		//wprintf(L"CreateProcessW\n");

		WCHAR cmd[16];
		wsprintf(cmd, L"p|%d", lpProcessInformation->dwProcessId);
		//SendMessageToMonitorServer(cmd);
		SendMessageToInternalServer(cmd);
	}
	else
	{
		//wprintf(L"CreateProcessW %s %s %s\n", lpApplicationName, lpCommandLine, lpCurrentDirectory);
		//wprintf(L"CreateProcessW\n");
	}

	size_t argsLen = 2;
	argsLen += lpApplicationName == NULL ? 0 : wcslen(lpApplicationName);
	argsLen += lpCommandLine == NULL ? 0 : wcslen(lpCommandLine);
	argsLen += lpCurrentDirectory == NULL ? 0 : wcslen(lpCurrentDirectory);

	PWCHAR args = (PWCHAR)malloc((argsLen + 1) * sizeof(WCHAR));
	wsprintf(args, L"%s*%s*%s", lpApplicationName == NULL ? L"" : lpApplicationName, lpCommandLine == NULL ? L"" : lpCommandLine, lpCurrentDirectory == NULL ? L"" : lpCurrentDirectory);
	
	PWCHAR cmd = (PWCHAR)malloc((wcslen(moduleName) + argsLen + 64) * sizeof(WCHAR));
	wsprintf(cmd, L"%s|%d|CreateProcess|%s|%d|%d", moduleName, processId, args, ret, err);
	if (args) {
		free(args);
		args = NULL;
	}
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}


CREATEPROCESSA fpCreateProcessA = NULL;

BOOL WINAPI DetourCreateProcessA(LPCSTR lpApplicationName,
									LPSTR lpCommandLine,
									LPSECURITY_ATTRIBUTES lpProcessAttributes,
									LPSECURITY_ATTRIBUTES lpThreadAttributes,
									BOOL bInheritHandles,
									DWORD dwCreationFlags,
									LPVOID lpEnvironment,
									LPCSTR lpCurrentDirectory,
									LPSTARTUPINFO lpStartupInfo,
									LPPROCESS_INFORMATION lpProcessInformation)
{
	
	BOOL ret = fpCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	DWORD err = GetLastError();

	if (ret)
	{
		//printf("CreateProcessA %s %s %s ProcessId %d\n", lpApplicationName, lpCommandLine, lpCurrentDirectory, lpProcessInformation->dwProcessId);
		//printf("CreateProcessA\n");

		WCHAR cmd[16];
		wsprintf(cmd, L"p|%d", lpProcessInformation->dwProcessId);
		//SendMessageToMonitorServer(cmd);
		SendMessageToInternalServer(cmd);
	}
	else
	{
		//printf("CreateProcessA %s %s %s\n", lpApplicationName, lpCommandLine, lpCurrentDirectory);
		//printf("CreateProcessA\n");
	}

	size_t argsLen = 2;
	argsLen += lpApplicationName == NULL ? 0 : strlen(lpApplicationName);
	argsLen += lpCommandLine == NULL ? 0 : strlen(lpCommandLine);
	argsLen += lpCurrentDirectory == NULL ? 0 : strlen(lpCurrentDirectory);

	PCHAR args = (PCHAR)malloc((argsLen + 1) * sizeof(CHAR));

	sprintf(args, "%s*%s*%s", lpApplicationName == NULL ? "" : lpApplicationName, lpCommandLine == NULL ? "" : lpCommandLine, lpCurrentDirectory == NULL ? "" : lpCurrentDirectory);

	PWCHAR argsW = (PWCHAR)malloc((argsLen + 1) * sizeof(WCHAR));
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, args, -1, argsW, argsLen + 1);
	PWCHAR cmd = (PWCHAR)malloc((wcslen(moduleName) + argsLen + 64) * sizeof(WCHAR));
	wsprintf(cmd, L"%s|%d|CreateProcess|%s|%d|%d", moduleName, processId, argsW, ret, err);
	if (args) {
		free(args);
		args = NULL;
	}
	if (argsW) {
		free(argsW);
		argsW = NULL;
	}
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}


//---------------------CreateRemoteThread---------------------


CREATEREMOTETHREAD fpCreateRemoteThread = NULL;

HANDLE WINAPI DetourCreateRemoteThread(HANDLE hProcess,
										LPSECURITY_ATTRIBUTES lpThreadAttributes,
										SIZE_T dwStackSize,
										LPTHREAD_START_ROUTINE lpStartAddress,
										LPVOID lpParameter,
										DWORD dwCreationFlags,
										LPDWORD lpThreadId)
{
	//wprintf(L"CreateRemoteThread\n");

	HANDLE ret = fpCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

	return ret;
}


//---------------------WriteFile---------------------


WRITEFILE fpWriteFile = NULL;

BOOL WINAPI DetourWriteFile(HANDLE hFile,
							LPCVOID lpBuffer,
							DWORD nNumberOfBytesToWrite,
							LPDWORD lpNumberOfBytesWritten,
							LPOVERLAPPED lpOverlapped)
{
	//wprintf(L"WriteFile\n");

	BOOL ret = fpWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

	return ret;
}


//---------------------ReadFile---------------------


READFILE fpReadFile = NULL;

BOOL WINAPI DetourReadFile(HANDLE hFile,
							LPVOID lpBuffer,
							DWORD nNumberOfBytesToRead,
							LPDWORD lpNumberOfBytesRead,
							LPOVERLAPPED lpOverlapped)
{
	//wprintf(L"ReadFile\n");

	BOOL ret = fpReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

	return ret;
}


//---------------------OpenFile---------------------


OPENFILE fpOpenFile = NULL;

HFILE WINAPI DetourOpenFile(LPCSTR lpFileName,
							LPOFSTRUCT lpReOpenBuff,
							UINT uStyle)
{
	//wprintf(L"OpenFile %s\n", lpFileName);
	//wprintf(L"OpenFile\n");

	HFILE ret = fpOpenFile(lpFileName, lpReOpenBuff, uStyle);

	return ret;
}


//---------------------CreateFile---------------------


CREATEFILEW fpCreateFileW = NULL;

HANDLE WINAPI DetourCreateFileW(LPCWSTR lpFileName,
								DWORD dwDesiredAccess,
								DWORD dwShareMode,
								LPSECURITY_ATTRIBUTES lpSecurityAttributes,
								DWORD dwCreationDisposition,
								DWORD dwFlagsAndAttributes,
								HANDLE hTemplateFile)
{
	//wprintf(L"CreateFileW %s %d\n", lpFileName, GetCurrentThreadId());
	//wprintf(L"CreateFileW\n");
	/*if (wcsstr(lpFileName, TEXT("\\\\.\\pipe\\"))){
		printf("CreateFileW PIPE.\n");
		fflush(stdout);
		HANDLE ret = fpCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
		return ret;
	}*/
	HANDLE ret = fpCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	DWORD err = GetLastError();

	PWCHAR cmd = NULL;
	while (!(cmd = (PWCHAR)malloc((wcslen(moduleName) + wcslen(lpFileName) + 64) * sizeof(WCHAR))));
	wsprintf(cmd, L"%s|%d|CreateFile|%s*%d|%d|%d", moduleName, processId, lpFileName == NULL ? L"\0": lpFileName, dwDesiredAccess, ret != INVALID_HANDLE_VALUE, err);
	
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);

	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}

CREATEFILEA fpCreateFileA = NULL;

HANDLE WINAPI DetourCreateFileA(LPCSTR lpFileName,
								DWORD dwDesiredAccess,
								DWORD dwShareMode,
								LPSECURITY_ATTRIBUTES lpSecurityAttributes,
								DWORD dwCreationDisposition,
								DWORD dwFlagsAndAttributes,
								HANDLE hTemplateFile)
{
	//printf("CreateFileA %s\n", lpFileName);
	//printf("CreateFileA\n");
	/*if (strstr(lpFileName, "\\\\.\\pipe\\")) {
		printf("CreateFileA PIPE.\n");
		fflush(stdout);
	}*/
	HANDLE ret = fpCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	DWORD err = GetLastError();

	size_t fileNameLen = lpFileName == NULL ? 0 : strlen(lpFileName);
	PWCHAR lpFileNameW = NULL;
	while (!(lpFileNameW = (PWCHAR)malloc((fileNameLen + 1) * sizeof(WCHAR))));
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, lpFileName, -1, lpFileNameW, fileNameLen + 1);
	PWCHAR cmd = (PWCHAR)malloc((wcslen(moduleName) + fileNameLen + 64) * sizeof(WCHAR));
	wsprintf(cmd, L"%s|%d|CreateFile|%s*%d|%d|%d", moduleName, processId, lpFileNameW, dwDesiredAccess, ret != INVALID_HANDLE_VALUE, err);
	
	if (lpFileNameW) {
		free(lpFileNameW);
		lpFileNameW = NULL;
	}
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}


//---------------------DeleteFile---------------------


DELETEFILEW fpDeleteFileW = NULL;

BOOL WINAPI DetourDeleteFileW(LPCWSTR lpFileName)
{
	//wprintf(L"DeleteFileW %s\n", lpFileName);
	//wprintf(L"DeleteFileW\n");

	BOOL ret = fpDeleteFileW(lpFileName);
	DWORD err = GetLastError();

	PWCHAR cmd = NULL;
	while (!(cmd = (PWCHAR)malloc((wcslen(moduleName) + (lpFileName == NULL ? 0 : wcslen(lpFileName)) + 64) * sizeof(WCHAR))));
	wsprintf(cmd, L"%s|%d|DeleteFile|%s|%d|%d", moduleName, processId, lpFileName == NULL ? L"\0": lpFileName, ret, err);

	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}

DELETEFILEA fpDeleteFileA = NULL;

BOOL WINAPI DetourDeleteFileA(LPCSTR lpFileName)
{
	//printf("DeleteFileA %s\n", lpFileName);
	//printf("DeleteFileA\n");
	BOOL ret = fpDeleteFileA(lpFileName);
	DWORD err = GetLastError();

	size_t fileNameLen = lpFileName == NULL ? 0 : strlen(lpFileName);
	PWCHAR lpFileNameW = NULL;
	while (!(lpFileNameW = (PWCHAR)malloc((fileNameLen + 1) * sizeof(WCHAR))));
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, lpFileName, -1, lpFileNameW, fileNameLen + 1);
	PWCHAR cmd = NULL;
	while (!(cmd = (PWCHAR)malloc((wcslen(moduleName) + fileNameLen + 64) * sizeof(WCHAR))));
	wsprintf(cmd, L"%s|%d|DeleteFile|%s|%d|%d", moduleName, processId, lpFileNameW, ret, err);
	if (lpFileNameW) {
		free(lpFileNameW);
		lpFileNameW = NULL;
	}

	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);

	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}


//---------------------RegCreateKeyEx---------------------


PWCHAR checkPredefinedKey(HKEY hKey, PWCHAR buf, DWORD bufSize)
{

	if (bufSize < 32)
	{
		return NULL;
	}
	if (hKey == HKEY_CLASSES_ROOT)
	{
		wcscpy(buf, L"HKEY_CLASSES_ROOT");
		return buf;
	}
	if (hKey == HKEY_CURRENT_USER)
	{
		wcscpy(buf, L"HKEY_CURRENT_USER");
		return buf;
	}
	if (hKey == HKEY_LOCAL_MACHINE)
	{
		wcscpy(buf, L"HKEY_LOCAL_MACHINE");
		return buf;
	}
	if (hKey == HKEY_USERS)
	{
		wcscpy(buf, L"HKEY_USERS");
		return buf;
	}
	if (hKey == HKEY_PERFORMANCE_DATA)
	{
		wcscpy(buf, L"HKEY_PERFORMANCE_DATA");
		return buf;
	}
	if (hKey == HKEY_PERFORMANCE_TEXT)
	{
		wcscpy(buf, L"HKEY_PERFORMANCE_TEXT");
		return buf;
	}
	if (hKey == HKEY_PERFORMANCE_NLSTEXT)
	{
		wcscpy(buf, L"HKEY_PERFORMANCE_NLSTEXT");
		return buf;
	}
	return NULL;
}

PWCHAR queryRegKey(HKEY hKey, PWCHAR buf, DWORD bufSize)
{
	PWCHAR result = checkPredefinedKey(hKey, buf, bufSize);
	if (result)
	{
		return result;
	}
	
	if (NtQueryKey && hKey) {
		DWORD size = 0;
		DWORD ret = NtQueryKey(hKey, 3, 0, 0, &size);
		//printf("ret 0x%08x\n", ret);
		if (ret == STATUS_BUFFER_TOO_SMALL)
		{
			if (bufSize < size + sizeof(WCHAR))
			{
				return NULL;
			}
			ret = NtQueryKey(hKey, 3, buf, size, &size);
			//printf("ret 0x%08x\n", ret);
			if (ret == STATUS_SUCCESS)
			{
				buf[size / sizeof(WCHAR)] = L'\0';
				//wprintf(L"%s\n", path + 2);
				return buf + 2;
			}
		}
	}

	return NULL;
}


REGCREATEKEYEXW fpRegCreateKeyExW = NULL;

LONG WINAPI DetourRegCreateKeyExW(HKEY hKey,
									LPCWSTR lpSubKey,
									DWORD Reserved,
									LPWSTR lpClass,
									DWORD dwOptions,
									REGSAM samDesired,
									LPSECURITY_ATTRIBUTES lpSecurityAttributes,
									PHKEY phkResult,
									LPDWORD lpdwDisposition)
{
	//wprintf(L"RegCreateKeyExW %s %s\n", lpSubKey, lpClass);
	//wprintf(L"RegCreateKeyExW\n");

	LONG ret = fpRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);

	return ret;
}

REGCREATEKEYEXA fpRegCreateKeyExA = NULL;

LONG WINAPI DetourRegCreateKeyExA(HKEY hKey,
									LPCSTR lpSubKey,
									DWORD Reserved,
									LPSTR lpClass,
									DWORD dwOptions,
									REGSAM samDesired,
									LPSECURITY_ATTRIBUTES lpSecurityAttributes,
									PHKEY phkResult,
									LPDWORD lpdwDisposition)
{
	//printf("RegCreateKeyExA %s %s\n", lpSubKey, lpClass);
	//printf("RegCreateKeyExA\n");

	LONG ret = fpRegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);

	return ret;
}


//---------------------RegCreateKey---------------------


REGCREATEKEYW fpRegCreateKeyW = NULL;

LONG WINAPI DetourRegCreateKeyW(HKEY hKey,
								LPCWSTR lpSubKey,
								PHKEY phkResult)
{
	//wprintf(L"RegCreateKeyW %s\n", lpSubKey);
	//wprintf(L"RegCreateKeyW\n");

	LONG ret = fpRegCreateKeyW(hKey, lpSubKey, phkResult);

	return ret;
}

REGCREATEKEYA fpRegCreateKeyA = NULL;

LONG WINAPI DetourRegCreateKeyA(HKEY hKey,
								LPCSTR lpSubKey,
								PHKEY phkResult)
{
	//printf("RegCreateKeyA %s\n", lpSubKey);
	//printf("RegCreateKeyA\n");

	LONG ret = fpRegCreateKeyA(hKey, lpSubKey, phkResult);

	return ret;
}


//---------------------RegSetValueEx---------------------


REGSETVALUEEXW fpRegSetValueExW = NULL;

LONG WINAPI DetourRegSetValueExW(HKEY hKey,
									LPCWSTR lpValueName,
									DWORD Reserved,
									DWORD dwType,
									const BYTE *lpData,
									DWORD cbData)
{
	//wprintf(L"RegSetValueEx %s\n", lpValueName);
	//wprintf(L"RegSetValueEx\n");

	LONG ret = fpRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
	DWORD err = GetLastError();

	PWCHAR path = (PWCHAR)malloc(MAX_PATH);
	PWCHAR result = queryRegKey(hKey, path, MAX_PATH);

	size_t argsLen = 2;
	argsLen += result == NULL? 0 : wcslen(result);
	argsLen += lpValueName == NULL ? 0 : wcslen(lpValueName);
	if (dwType == REG_SZ)
	{
		argsLen += lpData == NULL ? 0 : wcslen((PWCHAR)lpData);
	}
	else if (dwType == REG_DWORD)
	{
		argsLen += 16;
	}

	PWCHAR args = (PWCHAR)malloc((argsLen + 1) * sizeof(WCHAR));
	if (dwType == REG_SZ)
	{
		wsprintf(args, L"%s*%s*%s", result == NULL ? L"" : result, lpValueName == NULL ? L"" : lpValueName, lpData == NULL ? L"" : (PWCHAR)lpData);
	}
	else if (dwType == REG_DWORD)
	{
		wsprintf(args, L"%s*%s*%d", result == NULL ? L"" : result, lpValueName == NULL ? L"" : lpValueName, lpData == NULL ? 0 : *((DWORD *)lpData));
	}
	else
	{
		wsprintf(args, L"%s*%s:", result == NULL ? L"" : result, lpValueName == NULL ? L"" : lpValueName);
	}

	PWCHAR cmd = (PWCHAR)malloc((argsLen + 64) * sizeof(WCHAR));
	wsprintf(cmd, L"%s|%d|RegSetValueEx|%s|%d|%d", moduleName, processId, args, ret == ERROR_SUCCESS, err);
	
	if (path) {
		free(path);
		path = NULL;
	}

	if (args) {
		free(args);
		args = NULL;
	}
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}

REGSETVALUEEXA fpRegSetValueExA = NULL;

LONG WINAPI DetourRegSetValueExA(HKEY hKey,
									LPCSTR lpValueName,
									DWORD Reserved,
									DWORD dwType,
									const BYTE *lpData,
									DWORD cbData)
{
	//printf("RegSetValueExA %s\n", lpValueName);
	//printf("RegSetValueExA\n");

	LONG ret = fpRegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);

	return ret;
}


//---------------------RegOpenKeyEx---------------------


REGOPENKEYEXW fpRegOpenKeyExW = NULL;

LONG WINAPI DetourRegOpenKeyExW(HKEY hKey,
								LPCWSTR lpSubKey,
								DWORD ulOptions,
								REGSAM samDesired,
								PHKEY phkResult)
{
	//wprintf(L"RegOpenKeyEx %p %s\n", hKey, lpSubKey);
	//wprintf(L"RegOpenKeyEx\n");

	LONG ret = fpRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	DWORD err = GetLastError();

	PWCHAR path = (PWCHAR)malloc(MAX_PATH);
	PWCHAR result = queryRegKey(hKey, path, MAX_PATH);

	PWCHAR arg = (PWCHAR)malloc(((result == NULL ? 0 : wcslen(result)) + (lpSubKey == NULL? 0:wcslen(lpSubKey)) + 2) * sizeof(WCHAR));
	wsprintf(arg, L"%s*%s", result == NULL ? L"" : result, lpSubKey == NULL? L"": lpSubKey);

	PWCHAR cmd = (PWCHAR)malloc((wcslen(moduleName) + wcslen(arg) + 64) * sizeof(WCHAR));
	wsprintf(cmd, L"%s|%d|RegOpenKeyEx|%s|%d|%d", moduleName, processId, arg, ret != ERROR_SUCCESS, err);
	
	if (path) {
		free(path);
		path = NULL;
	}

	if (arg) {
		free(arg);
		arg = NULL;
	}
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}


REGOPENKEYEXA fpRegOpenKeyExA = NULL;

LONG WINAPI DetourRegOpenKeyExA(HKEY hKey,
								LPCSTR lpSubKey,
								DWORD ulOptions,
								REGSAM samDesired,
								PHKEY phkResult)
{
	//printf("RegOpenKeyEx %p %s\n", hKey, lpSubKey);
	//printf("RegOpenKeyEx\n");

	LONG ret = fpRegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	DWORD err = GetLastError();

	size_t subKeyLen = lpSubKey == NULL? 0:strlen(lpSubKey);
	PWCHAR lpSubKeyW = (PWCHAR)malloc((subKeyLen + 1) * sizeof(WCHAR));
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, lpSubKey == NULL? "": lpSubKey, -1, lpSubKeyW, subKeyLen + 1);

	PWCHAR path = (PWCHAR)malloc(MAX_PATH);
	PWCHAR result = queryRegKey(hKey, path, MAX_PATH);

	PWCHAR arg = (PWCHAR)malloc(((result == NULL ? 0 : wcslen(result)) + subKeyLen + 2) * sizeof(WCHAR));
	wsprintf(arg, L"%s*%s", result == NULL? L"": result, lpSubKeyW);
	
	PWCHAR cmd = (PWCHAR)malloc((wcslen(moduleName) + wcslen(arg) + 64) * sizeof(WCHAR));
	wsprintf(cmd, L"%s|%d|RegOpenKeyEx|%s|%d|%d", moduleName, processId, arg, ret != ERROR_SUCCESS, err);

	if (lpSubKeyW) {
		free(lpSubKeyW);
		lpSubKeyW = NULL;
	}

	if (path) {
		free(path);
		path = NULL;
	}

	if (arg) {
		free(arg);
		arg = NULL;
	}
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}


//---------------------RegQueryValueEx---------------------


REGQUERYVALUEEXW fpRegQueryValueExW = NULL;

LONG WINAPI DetourRegQueryValueExW(HKEY hKey,
									LPCWSTR lpValueName,
									LPDWORD lpReserved,
									LPDWORD lpType,
									LPBYTE  lpData,
									LPDWORD lpcbData)
{
	//wprintf(L"RegQueryValueEx %s\n", lpValueName);
	//wprintf(L"RegQueryValueEx\n");

	LONG ret = fpRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
	DWORD err = GetLastError();

	PWCHAR path = NULL;
	while (!(path = (PWCHAR)malloc(MAX_PATH)));
	PWCHAR result = queryRegKey(hKey, path, MAX_PATH);

	PWCHAR arg = NULL;
	while (!(arg = (PWCHAR)malloc(((result == NULL ? 0 : wcslen(result)) + (lpValueName == NULL ? 0 : wcslen(lpValueName)) + 2) * sizeof(WCHAR))));
	wsprintf(arg, L"%s*%s", result == NULL? L"": result, lpValueName == NULL? L"": lpValueName);

	PWCHAR cmd = NULL;
	while (!(cmd = (PWCHAR)malloc((wcslen(moduleName) + wcslen(arg) + 64) * sizeof(WCHAR))));
	wsprintf(cmd, L"%s|%d|RegQueryValueEx|%s|%d|%d", moduleName, processId, arg, ret != ERROR_SUCCESS, err);
	
	if (path) {
		free(path);
		path = NULL;
	}

	if (arg) {
		free(arg);
		arg = NULL;
	}
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}


REGQUERYVALUEEXA fpRegQueryValueExA = NULL;

LONG WINAPI DetourRegQueryValueExA(HKEY hKey,
									LPCSTR lpValueName,
									LPDWORD lpReserved,
									LPDWORD lpType,
									LPBYTE  lpData,
									LPDWORD lpcbData)
{
	//printf("RegQueryValueEx %s\n", lpValueName);
	//printf("RegQueryValueEx\n");

	LONG ret = fpRegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
	DWORD err = GetLastError();

	size_t valueNameLen = lpValueName? 0 : strlen(lpValueName);
	PWCHAR lpValueNameW = (PWCHAR)malloc((valueNameLen + 1) * sizeof(WCHAR));
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, lpValueName == NULL? "" : lpValueName, -1, lpValueNameW, valueNameLen + 1);

	PWCHAR path = NULL;
	while (!(path = (PWCHAR)malloc(MAX_PATH)));
	PWCHAR result = queryRegKey(hKey, path, MAX_PATH);

	PWCHAR arg = NULL;
	while (!(arg = (PWCHAR)malloc(((result == NULL ? 0 : wcslen(result)) + valueNameLen + 2) * sizeof(WCHAR))));
	wsprintf(arg, L"%s*%s", result == NULL? L"": result, lpValueNameW);

	PWCHAR cmd = NULL;
	while (!(cmd = (PWCHAR)malloc((wcslen(moduleName) + wcslen(arg) + 64) * sizeof(WCHAR))));
	wsprintf(cmd, L"%s|%d|RegQueryValueEx|%s|%d|%d", moduleName, processId, arg, ret != ERROR_SUCCESS, err);
	
	if (lpValueNameW) {
		free(lpValueNameW);
		lpValueNameW = NULL;
	}

	if (path) {
		free(path);
		path = NULL;
	}

	if (arg) {
		free(arg);
		arg = NULL;
	}
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}


//---------------------LoadLibrary---------------------


LOADLIBRARYW fpLoadLibraryW = NULL;

HMODULE WINAPI DetourLoadLibraryW(LPCWSTR lpFileName)
{

	HMODULE ret = fpLoadLibraryW(lpFileName);
	DWORD err = GetLastError();

	//wprintf(L"LoadLibraryW %s %d %p\n", lpFileName, GetCurrentThreadId(), ret);
	//wprintf(L"LoadLibraryW\n");

	PWCHAR cmd = (PWCHAR)malloc((wcslen(moduleName) + wcslen(lpFileName) + 64) * sizeof(WCHAR));
	wsprintf(cmd, L"%s|%d|LoadLibrary|%s|%d|%d", moduleName, processId, lpFileName, ret != NULL, err);
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}

LOADLIBRARYA fpLoadLibraryA = NULL;

HMODULE WINAPI DetourLoadLibraryA(LPCSTR lpFileName)
{
	HMODULE ret = fpLoadLibraryA(lpFileName);
	DWORD err = GetLastError();

	//printf("LoadLibraryA %s %d %p\n", lpFileName, GetCurrentThreadId(), ret);
	//printf("LoadLibraryA\n");

	size_t fileNameLen = strlen(lpFileName);
	PWCHAR lpFileNameW = NULL;
	while (!(lpFileNameW = (PWCHAR)malloc((fileNameLen + 1) * sizeof(WCHAR))));
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, lpFileName, -1, lpFileNameW, fileNameLen + 1);
	PWCHAR cmd = NULL;
	while (!(cmd = (PWCHAR)malloc((wcslen(moduleName) + fileNameLen + 64) * sizeof(WCHAR))));
	wsprintf(cmd, L"%s|%d|LoadLibrary|%s|%d|%d", moduleName, processId, lpFileNameW, ret != NULL, err);
	
	if (lpFileNameW) {
		free(lpFileNameW);
		lpFileNameW = NULL;
	}

	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}


//---------------------SetCurrentDirectory---------------------


SETCURRENTDIRECTORYW fpSetCurrentDirectoryW = NULL;

BOOL WINAPI DetourSetCurrentDirectoryW(LPCWSTR lpPathName)
{
	//wprintf(L"SetCurrentDirectory %s\n", lpPathName);
	//wprintf(L"SetCurrentDirectory\n");

	BOOL ret = fpSetCurrentDirectoryW(lpPathName);
	DWORD err = GetLastError();

	PWCHAR cmd = NULL;
	while (!(cmd = (PWCHAR)malloc((wcslen(lpPathName) + 64) * sizeof(WCHAR))));
	wsprintf(cmd, L"%s|%d|SetCurrentDirectory|%s|%d|%d", moduleName, processId, lpPathName, ret != 0, err);
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}

SETCURRENTDIRECTORYA fpSetCurrentDirectoryA = NULL;

BOOL WINAPI DetourSetCurrentDirectoryA(LPCSTR lpPathName)
{
	//printf("SetCurrentDirectory %s\n", lpPathName);
	//printf("SetCurrentDirectory\n");

	BOOL ret = fpSetCurrentDirectoryA(lpPathName);
	DWORD err = GetLastError();

	size_t pathNameLen = strlen(lpPathName);
	PWCHAR lpPathNameW = NULL;
	while(!(lpPathNameW = (PWCHAR)malloc((pathNameLen + 1) * sizeof(WCHAR))));
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, lpPathName, -1, lpPathNameW, pathNameLen + 1);

	PWCHAR cmd = NULL;
	while (!(cmd = (PWCHAR)malloc((pathNameLen + 64) * sizeof(WCHAR))));
	wsprintf(cmd, L"%s|%d|SetCurrentDirectory|%s|%d|%d", moduleName, processId, lpPathNameW, ret != 0, err);
	
	if (lpPathNameW) {
		free(lpPathNameW);
		lpPathNameW = NULL;
	}

	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}


//---------------------OutputDebugString---------------------


OUPUTDEBUGSTRINGW fpOutputDebugStringW = NULL;

void WINAPI DetourOutputDebugStringW(LPCWSTR _lpOutputString)
{
	//wprintf(L"OutputDebugString %s\n", _lpOutputString);
	//wprintf(L"OutputDebugString\n");

	fpOutputDebugStringW(_lpOutputString);

	PWCHAR lpOutputString = NULL;
	while (!(lpOutputString = (PWCHAR)malloc(sizeof(WCHAR) * wcslen(_lpOutputString))));
	for (int i = 0; i < wcslen(_lpOutputString); ++i)
	{
		lpOutputString[i] = _lpOutputString[i] == '\n' ? ' ' : _lpOutputString[i];
	}
	
	PWCHAR cmd = NULL;
	while (!(cmd = (PWCHAR)malloc((wcslen(moduleName) + wcslen(lpOutputString) + 64) * sizeof(WCHAR))));
	wsprintf(cmd, L"%s|%d|OutputDebugString|%s|%d|%d", moduleName, processId, lpOutputString, 0, 0);
	
	if (lpOutputString) {
		free(lpOutputString);
		lpOutputString = NULL;
	}

	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return;
}

OUPUTDEBUGSTRINGA fpOutputDebugStringA = NULL;

void WINAPI DetourOutputDebugStringA(LPCSTR _lpOutputString)
{
	//printf("OutputDebugString %s\n", _lpOutputString);
	//printf("OutputDebugString\n");

	fpOutputDebugStringA(_lpOutputString);

	PCHAR lpOutputString = NULL;
	while (!(lpOutputString = (PCHAR)malloc(sizeof(CHAR) * strlen(_lpOutputString))));
	for (int i = 0; i < strlen(_lpOutputString); ++i)
	{
		lpOutputString[i] = _lpOutputString[i] == '\n' ? ' ' : _lpOutputString[i];
	}

	size_t outputStringLen = strlen(lpOutputString);
	PWCHAR lpOutputStringW = NULL;
	while(!(lpOutputStringW = (PWCHAR)malloc((outputStringLen + 1) * sizeof(WCHAR))));
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, lpOutputString, -1, lpOutputStringW, outputStringLen + 1);

	PWCHAR cmd = NULL;
	while (!(cmd = (PWCHAR)malloc((wcslen(moduleName) + outputStringLen + 64) * sizeof(WCHAR))));
	wsprintf(cmd, L"%s|%d|OutputDebugString|%s|%d|%d", moduleName, processId, lpOutputStringW, 0, 0);

	if (lpOutputStringW) {
		free(lpOutputStringW);
		lpOutputStringW = NULL;
	}

	if (lpOutputString) {
		free(lpOutputString);
		lpOutputString = NULL;
	}
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return;
}


//---------------------MoveFileEx---------------------


MOVEFILEEXW fpMoveFileExW = NULL;

BOOL WINAPI DetourMoveFileExW(LPCWSTR _lpExistingFileName,
								LPCWSTR _lpNewFileName,
								DWORD dwFlags)
{
	//wprintf(L"MoveFileEx %s %s\n", lpExistingFileName, lpNewFileName);
	//wprintf(L"MoveFileEx\n");

	LPWSTR lpExistingFileName;
	LPWSTR lpNewFileName;

	if (_lpExistingFileName) {
		lpExistingFileName = (LPWSTR)_lpExistingFileName;
	}
	else {
		lpExistingFileName = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1 * sizeof(LPWSTR*));
		lpExistingFileName[0] = '\0';
	}

	if (_lpNewFileName) {
		lpNewFileName = (LPWSTR)_lpNewFileName;
	}
	else {
		lpNewFileName = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1 * sizeof(LPWSTR*));
		lpNewFileName[0] = '\0';
	}

	BOOL ret = fpMoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
	DWORD err = GetLastError();

	PWCHAR cmd = NULL;
	while (!(cmd = (PWCHAR)malloc((wcslen(moduleName) + wcslen(lpExistingFileName) + wcslen(lpNewFileName) + 64) * sizeof(WCHAR))));
	wsprintf(cmd, L"%s|%d|MoveFileEx|%s*%s|%d|%d", moduleName, processId, lpExistingFileName, lpNewFileName, ret != 0, err);
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}

MOVEFILEEXA fpMoveFileExA = NULL;

BOOL WINAPI DetourMoveFileExA(LPCSTR _lpExistingFileName,
								LPCSTR _lpNewFileName,
								DWORD dwFlags)
{
	//printf("MoveFileEx %s %s\n", lpExistingFileName, lpNewFileName);
	//printf("MoveFileEx\n");

	LPSTR lpExistingFileName;
	LPSTR lpNewFileName;

	if (_lpExistingFileName) {
		lpExistingFileName = (LPSTR)_lpExistingFileName;
	}
	else {
		lpExistingFileName = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1 * sizeof(LPWSTR*));
		lpExistingFileName[0] = '\0';
	}

	if (_lpNewFileName) {
		lpNewFileName = (LPSTR)_lpNewFileName;
	}
	else {
		lpNewFileName = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1 * sizeof(LPSTR*));
		lpNewFileName[0] = '\0';
	}

	BOOL ret = fpMoveFileExA(lpExistingFileName, lpNewFileName, dwFlags);
	DWORD err = GetLastError();

	size_t argsLen = strlen(lpExistingFileName) + strlen(lpNewFileName) + 1;
	PCHAR args = NULL;
	while(!(args = (PCHAR)malloc((argsLen + 1) * sizeof(CHAR))));
	sprintf(args, "%s*%s", lpExistingFileName, lpNewFileName);
	PWCHAR argsW = NULL;
	while (!(argsW = (PWCHAR)malloc((argsLen + 1) * sizeof(WCHAR))));
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, args, -1, argsW, argsLen + 1);

	PWCHAR cmd = NULL;
	while (!(cmd = (PWCHAR)malloc((wcslen(moduleName) + argsLen + 64) * sizeof(WCHAR))));
	wsprintf(cmd, L"%s|%d|MoveFileEx|%s|%d|%d", moduleName, processId, argsW, ret != 0, err);
	if (args) {
		free(args);
		args = NULL;
	}
	if (argsW) {
		free(argsW);
		argsW = NULL;
	}
	//SendMessageToMonitorServer(cmd);
	SendMessageToInternalServer(cmd);
	
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}
	return ret;
}