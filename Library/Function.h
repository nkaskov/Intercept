#pragma once

#include "stdafx.h"

#include <Shellapi.h>



DWORD WINAPI SendMessageFromInternalServer(LPVOID);

//---------------------ShellExecuteEx---------------------


typedef BOOL (__stdcall *SHELLEXECUTEEXW)(SHELLEXECUTEINFOW *pExecInfo);

BOOL __stdcall DetourShellExecuteExW(SHELLEXECUTEINFOW *pExecInfo);

extern SHELLEXECUTEEXW fpShellExecuteExW;


typedef BOOL (__stdcall *SHELLEXECUTEEXA)(SHELLEXECUTEINFOA *pExecInfo);

BOOL __stdcall DetourShellExecuteExA(SHELLEXECUTEINFOA *pExecInfo);

extern SHELLEXECUTEEXA fpShellExecuteExA;


//---------------------OpenProcess---------------------


typedef HANDLE (WINAPI *OPENPROCESS)(DWORD dwDesiredAccess,
										BOOL bInheritHandle,
										DWORD dwProcessId);

HANDLE WINAPI DetourOpenProcess(DWORD dwDesiredAccess,
								BOOL bInheritHandle,
								DWORD dwProcessId);

extern OPENPROCESS fpOpenProcess;


//---------------------CreateProcess---------------------


typedef BOOL (WINAPI *CREATEPROCESSW)(LPCWSTR lpApplicationName,
										LPWSTR lpCommandLine,
										LPSECURITY_ATTRIBUTES lpProcessAttributes,
										LPSECURITY_ATTRIBUTES lpThreadAttributes,
										BOOL bInheritHandles,
										DWORD dwCreationFlags,
										LPVOID lpEnvironment,
										LPCWSTR lpCurrentDirectory,
										LPSTARTUPINFO lpStartupInfo,
										LPPROCESS_INFORMATION lpProcessInformation);

BOOL WINAPI DetourCreateProcessW(LPCWSTR lpApplicationName,
									LPWSTR lpCommandLine,
									LPSECURITY_ATTRIBUTES lpProcessAttributes,
									LPSECURITY_ATTRIBUTES lpThreadAttributes,
									BOOL bInheritHandles,
									DWORD dwCreationFlags,
									LPVOID lpEnvironment,
									LPCWSTR lpCurrentDirectory,
									LPSTARTUPINFO lpStartupInfo,
									LPPROCESS_INFORMATION lpProcessInformation);

extern CREATEPROCESSW fpCreateProcessW;


typedef BOOL (WINAPI *CREATEPROCESSA)(LPCSTR lpApplicationName,
										LPSTR lpCommandLine,
										LPSECURITY_ATTRIBUTES lpProcessAttributes,
										LPSECURITY_ATTRIBUTES lpThreadAttributes,
										BOOL bInheritHandles,
										DWORD dwCreationFlags,
										LPVOID lpEnvironment,
										LPCSTR lpCurrentDirectory,
										LPSTARTUPINFO lpStartupInfo,
										LPPROCESS_INFORMATION lpProcessInformation);

BOOL WINAPI DetourCreateProcessA(LPCSTR lpApplicationName,
									LPSTR lpCommandLine,
									LPSECURITY_ATTRIBUTES lpProcessAttributes,
									LPSECURITY_ATTRIBUTES lpThreadAttributes,
									BOOL bInheritHandles,
									DWORD dwCreationFlags,
									LPVOID lpEnvironment,
									LPCSTR lpCurrentDirectory,
									LPSTARTUPINFO lpStartupInfo,
									LPPROCESS_INFORMATION lpProcessInformation);

extern CREATEPROCESSA fpCreateProcessA;


//---------------------CreateRemoteThread---------------------


typedef HANDLE (WINAPI *CREATEREMOTETHREAD)(HANDLE hProcess,
											LPSECURITY_ATTRIBUTES lpThreadAttributes,
											SIZE_T dwStackSize,
											LPTHREAD_START_ROUTINE lpStartAddress,
											LPVOID lpParameter,
											DWORD dwCreationFlags,
											LPDWORD lpThreadId);

HANDLE WINAPI DetourCreateRemoteThread(HANDLE hProcess,
										LPSECURITY_ATTRIBUTES lpThreadAttributes,
										SIZE_T dwStackSize,
										LPTHREAD_START_ROUTINE lpStartAddress,
										LPVOID lpParameter,
										DWORD dwCreationFlags,
										LPDWORD lpThreadId);

extern CREATEREMOTETHREAD fpCreateRemoteThread;


//---------------------WriteFile---------------------


typedef BOOL (WINAPI *WRITEFILE)(HANDLE hFile,
									LPCVOID lpBuffer,
									DWORD nNumberOfBytesToWrite,
									LPDWORD lpNumberOfBytesWritten,
									LPOVERLAPPED lpOverlapped);

BOOL WINAPI DetourWriteFile(HANDLE hFile,
							LPCVOID lpBuffer,
							DWORD nNumberOfBytesToWrite,
							LPDWORD lpNumberOfBytesWritten,
							LPOVERLAPPED lpOverlapped);

extern WRITEFILE fpWriteFile;

//---------------------ReadFile---------------------


typedef BOOL (WINAPI *READFILE)(HANDLE hFile,
								LPVOID lpBuffer,
								DWORD nNumberOfBytesToRead,
								LPDWORD lpNumberOfBytesRead,
								LPOVERLAPPED lpOverlapped);

BOOL WINAPI DetourReadFile(HANDLE hFile,
							LPVOID lpBuffer,
							DWORD nNumberOfBytesToRead,
							LPDWORD lpNumberOfBytesRead,
							LPOVERLAPPED lpOverlapped);

extern READFILE fpReadFile;


//---------------------OpenFile---------------------


typedef HFILE (WINAPI *OPENFILE)(LPCSTR lpFileName,
									LPOFSTRUCT lpReOpenBuff,
									UINT uStyle);

HFILE WINAPI DetourOpenFile(LPCSTR lpFileName,
							LPOFSTRUCT lpReOpenBuff,
							UINT uStyle);

extern OPENFILE fpOpenFile;

//---------------------CreateFile---------------------


typedef HANDLE (WINAPI *CREATEFILEW)(LPCWSTR lpFileName,
										DWORD dwDesiredAccess,
										DWORD dwShareMode,
										LPSECURITY_ATTRIBUTES lpSecurityAttributes,
										DWORD dwCreationDisposition,
										DWORD dwFlagsAndAttributes,
										HANDLE hTemplateFile);

HANDLE WINAPI DetourCreateFileW(LPCWSTR lpFileName,
								DWORD dwDesiredAccess,
								DWORD dwShareMode,
								LPSECURITY_ATTRIBUTES lpSecurityAttributes,
								DWORD dwCreationDisposition,
								DWORD dwFlagsAndAttributes,
								HANDLE hTemplateFile);

extern CREATEFILEW fpCreateFileW;

typedef HANDLE (WINAPI *CREATEFILEA)(LPCSTR lpFileName,
										DWORD dwDesiredAccess,
										DWORD dwShareMode,
										LPSECURITY_ATTRIBUTES lpSecurityAttributes,
										DWORD dwCreationDisposition,
										DWORD dwFlagsAndAttributes,
										HANDLE hTemplateFile);

HANDLE WINAPI DetourCreateFileA(LPCSTR lpFileName,
								DWORD dwDesiredAccess,
								DWORD dwShareMode,
								LPSECURITY_ATTRIBUTES lpSecurityAttributes,
								DWORD dwCreationDisposition,
								DWORD dwFlagsAndAttributes,
								HANDLE hTemplateFile);

extern CREATEFILEA fpCreateFileA;


//---------------------DeleteFile---------------------


typedef BOOL (WINAPI *DELETEFILEW)(LPCWSTR lpFileName);

BOOL WINAPI DetourDeleteFileW(LPCWSTR lpFileName);

extern DELETEFILEW fpDeleteFileW;

typedef BOOL (WINAPI *DELETEFILEA)(LPCSTR lpFileName);

BOOL WINAPI DetourDeleteFileA(LPCSTR lpFileName);

extern DELETEFILEA fpDeleteFileA;


//---------------------RegCreateKeyEx---------------------


typedef LONG (WINAPI *REGCREATEKEYEXW)(HKEY hKey,
										LPCWSTR lpSubKey,
										DWORD Reserved,
										LPWSTR lpClass,
										DWORD dwOptions,
										REGSAM samDesired,
										LPSECURITY_ATTRIBUTES lpSecurityAttributes,
										PHKEY phkResult,
										LPDWORD lpdwDisposition);

LONG WINAPI DetourRegCreateKeyExW(HKEY hKey,
									LPCWSTR lpSubKey,
									DWORD Reserved,
									LPWSTR lpClass,
									DWORD dwOptions,
									REGSAM samDesired,
									LPSECURITY_ATTRIBUTES lpSecurityAttributes,
									PHKEY phkResult,
									LPDWORD lpdwDisposition);

extern REGCREATEKEYEXW fpRegCreateKeyExW;

typedef LONG (WINAPI *REGCREATEKEYEXA)(HKEY hKey,
										LPCSTR lpSubKey,
										DWORD Reserved,
										LPSTR lpClass,
										DWORD dwOptions,
										REGSAM samDesired,
										LPSECURITY_ATTRIBUTES lpSecurityAttributes,
										PHKEY phkResult,
										LPDWORD lpdwDisposition);

LONG WINAPI DetourRegCreateKeyExA(HKEY hKey,
									LPCSTR lpSubKey,
									DWORD Reserved,
									LPSTR lpClass,
									DWORD dwOptions,
									REGSAM samDesired,
									LPSECURITY_ATTRIBUTES lpSecurityAttributes,
									PHKEY phkResult,
									LPDWORD lpdwDisposition);

extern REGCREATEKEYEXA fpRegCreateKeyExA;


//---------------------RegCreateKey---------------------


typedef LONG (WINAPI *REGCREATEKEYW)(HKEY hKey,
										LPCWSTR lpSubKey,
										PHKEY phkResult);

LONG WINAPI DetourRegCreateKeyW(HKEY hKey,
								LPCWSTR lpSubKey,
								PHKEY phkResult);

extern REGCREATEKEYW fpRegCreateKeyW;

typedef LONG (WINAPI *REGCREATEKEYA)(HKEY hKey,
										LPCSTR lpSubKey,
										PHKEY phkResult);

LONG WINAPI DetourRegCreateKeyA(HKEY hKey,
								LPCSTR lpSubKey,
								PHKEY phkResult);

extern REGCREATEKEYA fpRegCreateKeyA;


//---------------------RegSetValueEx---------------------


typedef LONG (WINAPI *REGSETVALUEEXW)(HKEY hKey,
										LPCWSTR lpValueName,
										DWORD Reserved,
										DWORD dwType,
										const BYTE *lpData,
										DWORD cbData);

LONG WINAPI DetourRegSetValueExW(HKEY hKey,
									LPCWSTR lpValueName,
									DWORD Reserved,
									DWORD dwType,
									const BYTE *lpData,
									DWORD cbData);

extern REGSETVALUEEXW fpRegSetValueExW;

typedef LONG (WINAPI *REGSETVALUEEXA)(HKEY hKey,
										LPCSTR lpValueName,
										DWORD Reserved,
										DWORD dwType,
										const BYTE *lpData,
										DWORD cbData);

LONG WINAPI DetourRegSetValueExA(HKEY hKey,
									LPCSTR lpValueName,
									DWORD Reserved,
									DWORD dwType,
									const BYTE *lpData,
									DWORD cbData);

extern REGSETVALUEEXA fpRegSetValueExA;


//---------------------RegOpenKeyEx---------------------


typedef LONG (WINAPI *REGOPENKEYEXW)(HKEY hKey,
										LPCWSTR lpSubKey,
										DWORD ulOptions,
										REGSAM samDesired,
										PHKEY phkResult);

LONG WINAPI DetourRegOpenKeyExW(HKEY hKey,
								LPCWSTR lpSubKey,
								DWORD ulOptions,
								REGSAM samDesired,
								PHKEY phkResult);

extern REGOPENKEYEXW fpRegOpenKeyExW;


typedef LONG (WINAPI *REGOPENKEYEXA)(HKEY hKey,
										LPCSTR lpSubKey,
										DWORD ulOptions,
										REGSAM samDesired,
										PHKEY phkResult);

LONG WINAPI DetourRegOpenKeyExA(HKEY hKey,
								LPCSTR lpSubKey,
								DWORD ulOptions,
								REGSAM samDesired,
								PHKEY phkResult);

extern REGOPENKEYEXA fpRegOpenKeyExA;


//---------------------RegQueryValueEx---------------------


typedef LONG (WINAPI *REGQUERYVALUEEXW)(HKEY hKey,
										LPCWSTR lpValueName,
										LPDWORD lpReserved,
										LPDWORD lpType,
										LPBYTE  lpData,
										LPDWORD lpcbData);

LONG WINAPI DetourRegQueryValueExW(HKEY hKey,
									LPCWSTR lpValueName,
									LPDWORD lpReserved,
									LPDWORD lpType,
									LPBYTE  lpData,
									LPDWORD lpcbData);

extern REGQUERYVALUEEXW fpRegQueryValueExW;

typedef LONG (WINAPI *REGQUERYVALUEEXA)(HKEY hKey,
										LPCSTR lpValueName,
										LPDWORD lpReserved,
										LPDWORD lpType,
										LPBYTE  lpData,
										LPDWORD lpcbData);

LONG WINAPI DetourRegQueryValueExA(HKEY hKey,
									LPCSTR lpValueName,
									LPDWORD lpReserved,
									LPDWORD lpType,
									LPBYTE  lpData,
									LPDWORD lpcbData);

extern REGQUERYVALUEEXA fpRegQueryValueExA;


//---------------------LoadLibrary---------------------


typedef HMODULE (WINAPI *LOADLIBRARYW)(LPCWSTR lpFileName);

HMODULE WINAPI DetourLoadLibraryW(LPCWSTR lpFileName);

extern LOADLIBRARYW fpLoadLibraryW;

typedef HMODULE(WINAPI *LOADLIBRARYA)(LPCSTR lpFileName);

HMODULE WINAPI DetourLoadLibraryA(LPCSTR lpFileName);

extern LOADLIBRARYA fpLoadLibraryA;


//---------------------SetCurrentDirectory---------------------


typedef BOOL (WINAPI *SETCURRENTDIRECTORYW)(LPCWSTR lpPathName);

BOOL WINAPI DetourSetCurrentDirectoryW(LPCWSTR lpPathName);

extern SETCURRENTDIRECTORYW fpSetCurrentDirectoryW;


typedef BOOL (WINAPI *SETCURRENTDIRECTORYA)(LPCSTR lpPathName);

BOOL WINAPI DetourSetCurrentDirectoryA(LPCSTR lpPathName);

extern SETCURRENTDIRECTORYA fpSetCurrentDirectoryA;


//---------------------OutputDebugString---------------------


typedef void (WINAPI *OUPUTDEBUGSTRINGW)(LPCWSTR lpOutputString);

void WINAPI DetourOutputDebugStringW(LPCWSTR lpOutputString);

extern OUPUTDEBUGSTRINGW fpOutputDebugStringW;


typedef void (WINAPI *OUPUTDEBUGSTRINGA)(LPCSTR lpOutputString);

void WINAPI DetourOutputDebugStringA(LPCSTR lpOutputString);

extern OUPUTDEBUGSTRINGA fpOutputDebugStringA;


//---------------------MoveFileEx---------------------


typedef BOOL (WINAPI *MOVEFILEEXW)(LPCWSTR lpExistingFileName, 
									LPCWSTR lpNewFileName,
									DWORD dwFlags);

BOOL WINAPI DetourMoveFileExW(LPCWSTR lpExistingFileName,
								LPCWSTR lpNewFileName,
								DWORD dwFlags);

extern MOVEFILEEXW fpMoveFileExW;


typedef BOOL (WINAPI *MOVEFILEEXA)(LPCSTR lpExistingFileName,
									LPCSTR lpNewFileName,
									DWORD dwFlags);

BOOL WINAPI DetourMoveFileExA(LPCSTR lpExistingFileName,
								LPCSTR lpNewFileName,
								DWORD dwFlags);

extern MOVEFILEEXA fpMoveFileExA;
