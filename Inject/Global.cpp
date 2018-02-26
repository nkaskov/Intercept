#include "stdafx.h"
#include "Global.h"
#include "tinyxml2.h"
#include "utlist.h"
#include <TlHelp32.h>

struct processInfo *globalList;
struct processInfo *trashList;
struct mutantInfo *mutantsList;
struct filerequestsInfo *filerequestsList;
WCHAR binaryPath[2 * MAX_PATH];
WCHAR dllPathX64[MAX_PATH];
WCHAR dllPathX86[MAX_PATH];
WCHAR interlayerPath[MAX_PATH];
WCHAR outputPath[2 * MAX_PATH];

CHAR networkInterface[128];

using namespace std;
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI *_NtDuplicateObject)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options);
typedef NTSTATUS(NTAPI *_NtQueryObject)(HANDLE ObjectHandle, ULONG ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

using namespace std;

static PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

static _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQuerySystemInformation");
_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtDuplicateObject");
_NtQueryObject NtQueryObject = (_NtQueryObject)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQueryObject");

struct QueryStructure
{
	HANDLE dupHandle;
	PVOID objectNameInfo;
	ULONG objectInfoLength;
	ULONG returnLength;
	NTSTATUS result;
};

static HANDLE beginQuery = CreateEvent(0, FALSE, FALSE, 0);
static HANDLE endQuery = CreateEvent(0, FALSE, FALSE, 0);
static QueryStructure queryStructure;


static DWORD WINAPI queryThread(LPVOID parameter)
{
	while (WaitForSingleObject(beginQuery, INFINITE) == WAIT_OBJECT_0)
	{
		queryStructure.result = NtQueryObject(queryStructure.dupHandle, ObjectNameInformation, queryStructure.objectNameInfo, queryStructure.objectInfoLength, &queryStructure.returnLength);
		SetEvent(endQuery);
	}
	return 0;
}

static HANDLE queryThreadHandle = CreateThread(0, 0, &queryThread, 0, 0, 0);

PWSTR GetFileInternalNameByHandle(HANDLE handle)
{
	if (handle == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	DWORD   CharCount = 0;
	WCHAR   DeviceName[MAX_PATH] = L"";
	HANDLE  FindHandle = INVALID_HANDLE_VALUE;
	size_t  Index = 0;
	BOOL    Success = FALSE;

	FindHandle = INVALID_HANDLE_VALUE;
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle;
	ULONG i;
	DWORD pid;
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);
	pid = GetCurrentProcessId();
	if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid)))
	{
		return NULL;
	}
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	}
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}
	HANDLE dupHandle = NULL;
	POBJECT_TYPE_INFORMATION objectTypeInfo;
	PVOID objectNameInfo;
	UNICODE_STRING objectName;
	ULONG returnLength = 0;
	if (!NT_SUCCESS(NtDuplicateObject(processHandle, handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
	{
		return NULL;
	}
	objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
	size_t currentSize = 0x1000;
	objectNameInfo = malloc(currentSize);
	queryStructure.dupHandle = dupHandle;
	queryStructure.objectNameInfo = objectNameInfo;
	queryStructure.objectInfoLength = 0x1000;
	queryStructure.returnLength = returnLength;
	queryStructure.result = -1;
	SetEvent(beginQuery);
	if (WaitForSingleObject(endQuery, 100) == WAIT_TIMEOUT)
	{
		TerminateThread(queryThreadHandle, 1);
		CloseHandle(queryThreadHandle);
		queryThreadHandle = CreateThread(0, 0, &queryThread, 0, 0, 0);
		CloseHandle(dupHandle);
		return NULL;
	}
	if (!NT_SUCCESS(queryStructure.result))
	{
		objectNameInfo = realloc(objectNameInfo, currentSize *= 2);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL)))
		{
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			return NULL;
		}
	}
	objectName = *(PUNICODE_STRING)objectNameInfo;
	if (objectName.Length)
	{
		wprintf(L"Found %s.\n", objectName.Buffer);
		return objectName.Buffer;
	}
	free(objectTypeInfo);
	free(objectNameInfo);
	CloseHandle(dupHandle);

	free(handleInfo);
	CloseHandle(processHandle);
	return NULL;
}

PWSTR GetFileInternalNameByStrA(const char * file_requests_name) {
	auto internal_handle = CreateFileA(file_requests_name,
		0,
		0,                      // do not share
		NULL,                   // default security
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);
	printf("Search for%s %u %u\n", file_requests_name, internal_handle, internal_handle == INVALID_HANDLE_VALUE);
	return GetFileInternalNameByHandle(internal_handle);
}

PWCHAR GetConfigPathFromRegistry(void) {
	HKEY hk;
	DWORD dwType;

	DWORD dwBytes = 256;
	WCHAR *files_path = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytes);

	if (ERROR_SUCCESS != RegCreateKey(HKEY_CLASSES_ROOT,
		_T("Windows"),

		&hk)) {
		wprintf(_T("NO KEY"));
		fflush(stdout);
		HeapFree(GetProcessHeap(), 0x00, files_path);
		return NULL;
	}
	printf("Key open.\n");
	fflush(stdout);

	LONG result_reg = RegQueryValueEx(hk,
		_T("ConfigFile"),
		NULL,
		&dwType,
		(LPBYTE)files_path,
		&dwBytes);
	if (ERROR_SUCCESS == result_reg) {

		RegDeleteValue(hk, _T("ConfigFile"));

		RegCloseKey(hk);

		printf("Subkey open.\n");
		fflush(stdout);
		return files_path;

	}
	else {

		printf("Subkey failed to open GLE = %u.\n", GetLastError());
		fflush(stdout);
		return NULL;
	}
}

int parseConfig()
{
	PWCHAR config_file = GetConfigPathFromRegistry();

	char config_file_char[256];

	if (config_file && PathFileExists(config_file)) {

		DWORD len = wcstombs(config_file_char, config_file, wcslen(config_file));
		if (len > 0)
			config_file_char[len] = '\0';
	}
	else {
		const char default_path[] = "c:\\data\\config";
		printf("No registry key found or the path in registry is wrong. GLE = %u. Using default path: %s\n", GetLastError(), default_path);
		fflush(stdout);
		strcpy_s(config_file_char, 256, default_path);
	}
	printf("Open file %s.\n", config_file_char);
	fflush(stdout);
	WCHAR w_config_file_char[256];
	mbstowcs(w_config_file_char, config_file_char, 256);
	if (!PathFileExists(w_config_file_char)) {
		return 1;
	}
	tinyxml2::XMLDocument doc(true, tinyxml2::COLLAPSE_WHITESPACE);
	if (doc.LoadFile(config_file_char) == tinyxml2::XML_SUCCESS)
	{
		tinyxml2::XMLElement *settings = doc.FirstChildElement("settings");
		if (!settings)
		{
			return 1;
		}

		tinyxml2::XMLElement *general = settings->FirstChildElement("general");
		if (!general)
		{
			return 1;
		}


		tinyxml2::XMLElement *binarypath = general->FirstChildElement("binarypath");
		if (!binarypath)
		{
			return 1;
		}
		if (!MultiByteToWideChar(CP_ACP, 0, binarypath->GetText(), -1, binaryPath, sizeof(binaryPath)))
		{
			return 1;
		}
		PathCombine(dllPathX64, binaryPath, L"Library-x64.dll");
		PathCombine(dllPathX86, binaryPath, L"Library-x86.dll");
#if defined _M_X64
		PathCombine(interlayerPath, binaryPath, L"Hook-x86.exe");
#elif defined _M_IX86
		PathCombine(interlayerPath, binaryPath, L"Hook-x64.exe");
#endif
		_tprintf(TEXT("DllPath X64: %s\n"), dllPathX64);
		_tprintf(TEXT("DllPath X86: %s\n"), dllPathX86);
		_tprintf(TEXT("InterlayerPath: %s\n"), interlayerPath);

		tinyxml2::XMLElement *outputpath = general->FirstChildElement("outputpath");
		if (!outputpath)
		{
			return 1;
		}
		if (!MultiByteToWideChar(CP_ACP, 0, outputpath->GetText(), -1, outputPath, sizeof(outputPath)))
		{
			return 1;
		}
		_tprintf(TEXT("Output: %s\n"), outputPath);
		tinyxml2::XMLElement *networkinterface = general->FirstChildElement("interface");
		if (!networkinterface)
		{
			return 1;
		}
		strcpy(networkInterface, networkinterface->GetText());
		_tprintf(TEXT("Interface: %S\n"), networkInterface);

		tinyxml2::XMLElement *processlist = settings->FirstChildElement("processlist");
		if (!processlist)
		{
			return 1;
		}

		tinyxml2::XMLElement *process = processlist->FirstChildElement("process");
		if (!process)
		{
			return 1;
		}
		do
		{
			struct processInfo *item = NULL;
			while (!(item = (struct processInfo *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct processInfo))));
			struct mutantInfo *mutant_item = NULL;
			while (!(mutant_item = (struct mutantInfo *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct mutantInfo))));
			struct filerequestsInfo *file_requests_item = NULL;
			while (!(file_requests_item = (struct filerequestsInfo *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct filerequestsInfo))));

			const char *name = process->Attribute("name");
			if (name)
			{
				if (!MultiByteToWideChar(CP_ACP, 0, name, -1, item->processName, MAX_IMAGE))
				{
					HeapFree(GetProcessHeap(), 0x00, item);
					HeapFree(GetProcessHeap(), 0x00, mutant_item);
					HeapFree(GetProcessHeap(), 0x00, file_requests_item);
					return 1;
				}
				item->persistent = TRUE;
			}
			else
			{
				const char *pid = process->Attribute("pid");
				if (!pid)
				{
					const char *mutant_name = process->Attribute("mutant_name");
					
					if (mutant_name)
					{
						
						if (!MultiByteToWideChar(CP_ACP, 0, mutant_name, -1, mutant_item->mutant_name, MAX_IMAGE))
						{
							return 1;
						}
						mutant_item->persistent = TRUE;
					}
					else {
						const char *file_requests_name = process->Attribute("file_requests_name");

						if (file_requests_name)
						{
						
							/*if (!MultiByteToWideChar(CP_ACP, 0, file_requests_name, -1, file_requests_item->file_requests_name, MAX_IMAGE))
							{
								return 1;
							}
							a*/
							PWSTR tmp_file_requests_name = GetFileInternalNameByStrA(file_requests_name);
							if (!tmp_file_requests_name) {
								return 1;
							}
							wcscpy(file_requests_item->file_requests_name, tmp_file_requests_name);
							file_requests_item->persistent = TRUE;
						}
						else {
							return 1;
						}

						const char *delay = process->Attribute("delay");
						if (delay)
						{
							file_requests_item->delay = atoi(delay);
						}
						else
						{
							file_requests_item->delay = DEFAULT_DELAY;
						}

						const char *hook = process->Attribute("hook");
						if (hook && strcmp(hook, "enable") == 0)
						{
							file_requests_item->hook = TRUE;
						}

						const char *network = process->Attribute("network");
						if (network && strcmp(network, "enable") == 0)
						{
							file_requests_item->network = TRUE;
						}

						const char *dump = process->Attribute("dump");
						if (dump && strcmp(dump, "enable") == 0)
						{
							file_requests_item->dump = TRUE;
						}

						const char *dumpinterval = process->Attribute("dumpinterval");
						if (dumpinterval)
						{
							file_requests_item->dumpInterval = atoi(dumpinterval);
						}
						else
						{
							file_requests_item->dumpInterval = DEFAULT_DUMPINTERVAL;
						}

						DL_APPEND(filerequestsList, file_requests_item);
						_tprintf(TEXT("File_requests (%s), delay %d, hook %d, network %d, dump %d, dumpInterval %d\n"), file_requests_item->file_requests_name, file_requests_item->delay, file_requests_item->hook, file_requests_item->network, file_requests_item->dump, file_requests_item->dumpInterval);
						continue;
					}


					const char *delay = process->Attribute("delay");
					if (delay)
					{
						mutant_item->delay = atoi(delay);
					}
					else
					{
						mutant_item->delay = DEFAULT_DELAY;
					}

					const char *hook = process->Attribute("hook");
					if (hook && strcmp(hook, "enable") == 0)
					{
						mutant_item->hook = TRUE;
					}

					const char *network = process->Attribute("network");
					if (network && strcmp(network, "enable") == 0)
					{
						mutant_item->network = TRUE;
					}

					const char *dump = process->Attribute("dump");
					if (dump && strcmp(dump, "enable") == 0)
					{
						mutant_item->dump = TRUE;
					}

					const char *dumpinterval = process->Attribute("dumpinterval");
					if (dumpinterval)
					{
						mutant_item->dumpInterval = atoi(dumpinterval);
					}
					else
					{
						mutant_item->dumpInterval = DEFAULT_DUMPINTERVAL;
					}

					DL_APPEND(mutantsList, mutant_item);
					_tprintf(TEXT("Mutant (%s), delay %d, hook %d, network %d, dump %d, dumpInterval %d\n"), mutant_item->mutant_name, mutant_item->delay, mutant_item->hook, mutant_item->network, mutant_item->dump, mutant_item->dumpInterval);
					continue;
				}
				item->running = TRUE;
				item->pidList[0] = atoi(pid);
				item->pidCount = 1;
			}


			const char *delay = process->Attribute("delay");
			if (delay)
			{
				item->delay = atoi(delay);
			}
			else
			{
				item->delay = DEFAULT_DELAY;
			}
			
			const char *hook = process->Attribute("hook");
			if (hook && strcmp(hook, "enable") == 0)
			{
				item->hook = TRUE;
			}

			const char *network = process->Attribute("network");
			if (network && strcmp(network, "enable") == 0)
			{
				item->network = TRUE;
			}

			const char *dump = process->Attribute("dump");
			if (dump && strcmp(dump, "enable") == 0)
			{
				item->dump = TRUE;
			}

			const char *dumpinterval = process->Attribute("dumpinterval");
			if (dumpinterval)
			{
				item->dumpInterval = atoi(dumpinterval);
			}
			else
			{
				item->dumpInterval = DEFAULT_DUMPINTERVAL;
			}

			DL_APPEND(globalList, item);
			_tprintf(TEXT("Process (%s), ProcessId %u, delay %d, hook %d, network %d, dump %d, dumpInterval %d\n"), item->processName, item->pidList[0], item->delay, item->hook, item->network, item->dump, item->dumpInterval);


		} while ((process = process->NextSiblingElement("process")));
	}
	return 0;
}

int initGlobal()
{
	globalList = NULL;
	trashList = NULL;
	if (parseConfig())
	{
		return 1;
	}

	return 0;
}