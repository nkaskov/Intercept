#include "FileRequests.h"

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

struct QueryStructure
{
	HANDLE dupHandle;
	PVOID objectNameInfo;
	ULONG objectInfoLength;
	ULONG returnLength;
	NTSTATUS result;
};

static PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

static _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQuerySystemInformation");
static _NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtDuplicateObject");
static _NtQueryObject NtQueryObject = (_NtQueryObject)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQueryObject");

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

void CheckForLocks()
{
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle;
	ULONG i;
	DWORD pid;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);
	if (Process32First(snapshot, &process))
	{
		do
		{
			pid = process.th32ProcessID;
			if (pid == GetCurrentProcessId()) {
				continue;
			}
			if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid)))
			{
				continue;
			}
			handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
			while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
			{
				handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
			}
			if (!NT_SUCCESS(status))
			{
				return;
			}
			for (i = 0; i < handleInfo->HandleCount; i++)
			{
				SYSTEM_HANDLE handle = handleInfo->Handles[i];
				HANDLE dupHandle = NULL;
				POBJECT_TYPE_INFORMATION objectTypeInfo;
				PVOID objectNameInfo;
				UNICODE_STRING objectName;
				ULONG returnLength = 0;
				if (handle.ProcessId != pid)
					continue;
				if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
				{
					continue;
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
					continue;
				}
				if (!NT_SUCCESS(queryStructure.result))
				{
					objectNameInfo = realloc(objectNameInfo, currentSize *= 2);
					if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL)))
					{
						free(objectTypeInfo);
						free(objectNameInfo);
						CloseHandle(dupHandle);
						continue;
					}
				}
				objectName = *(PUNICODE_STRING)objectNameInfo;
				if (objectName.Length)
				{
					struct filerequestsInfo *file_requests_item;
					DL_FOREACH(filerequestsList, file_requests_item) {
						if (wcsstr(objectName.Buffer, file_requests_item->file_requests_name)) {
							printf(
								"%u\t [%#x]\t %.*S: %.*S\n",
								pid,
								handle.Handle,
								objectTypeInfo->Name.Length / 2,
								objectTypeInfo->Name.Buffer,
								objectName.Length / 2,
								objectName.Buffer
							);
							AddNewProcess(pid, file_requests_item->hook, file_requests_item->delay, file_requests_item->network, file_requests_item->dump, file_requests_item->dumpInterval);
							break;
						}
					}
				}
				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
			}
			free(handleInfo);
			CloseHandle(processHandle);
		} while (Process32Next(snapshot, &process));
	}
}		

void _startFileRequestsMonitor() {
	while (TRUE) {
		CheckForLocks();
		Sleep(100);
	}
}

DWORD WINAPI startFileRequestsMonitor(thread **worker = nullptr)
{
	auto *myWorker = new thread(_startFileRequestsMonitor);
	if (worker != nullptr)
	{
		*worker = myWorker;
	}

	return 0;
}
