#include "stdafx.h"
#include "Global.h"
#include "Utils.h"
#include "Mutants.h"
#include "utlist.h"
#include <time.h>
#include <Winternl.h>


#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);
/*
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;*/

typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
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

static PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName) {
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

DWORD AddNewProcess(DWORD processId, BOOL hook = TRUE, DWORD delay = DEFAULT_DELAY, BOOL network = TRUE, BOOL dump = TRUE, DWORD dumpinterval = DEFAULT_DUMPINTERVAL) {
	struct processInfo *item;
	DL_FOREACH(globalList, item) {
		for (DWORD i = 0; i < item->pidCount; ++i) {
			if (item->pidList[i] == processId) {
				return 0;
			}
		}
	}

	while (!(item = (struct processInfo *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct processInfo))));
	GetProcessName(processId, item->processName, MAX_IMAGE);

	item->running = TRUE;
	item->pidList[0] = processId;
	item->pidCount = 1;
	item->hook = hook;
	item->delay = delay;
	item->network = network;
	item->dump = dump;
	item->dumpInterval = dumpinterval;

	_tprintf(TEXT("Adding new process %s with ProcessId %d\n"), item->processName, processId);

	DL_APPEND(globalList, item);
	return 0;
}

void FindMutantByName()
{
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x500;

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfoSize);

	while ((status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH) {
		PSYSTEM_HANDLE_INFORMATION tmp_handleInfo = NULL;
		while (!(tmp_handleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfo, handleInfoSize *= 2)));
		handleInfo = tmp_handleInfo;
	}
	if (!NT_SUCCESS(status)) {
		HeapFree(GetProcessHeap(), 0x00, handleInfo);
		printf("NtQuerySystemInformation failed! GLE=%d\n", GetLastError());
		return;
	}

	for (DWORD i = 0; i < handleInfo->HandleCount; i++) {

		TCHAR *current_process_name = L"-";

		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;

		DWORD handle_ProcessId = handle.ProcessId;

		if (handle_ProcessId == GetCurrentProcessId()) {
			continue;
		}

		//printf("PID %d\n", handle_ProcessId);
		fflush(stdout);

		HANDLE processHandle;

		if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle_ProcessId))) {
			//printf("Could not open PID %d! (Don't try to open a system process.) GLE = %d.\n", handle_ProcessId, GetLastError());
			continue;
		}


		if (!(DuplicateHandle(processHandle,
			(void*)handle.Handle,
			GetCurrentProcess(),
			&dupHandle,
			0,
			FALSE,
			DUPLICATE_SAME_ACCESS))) {
			//printf("Could not duplicate Handle in PID %d! GLE = %d.\n", handle_ProcessId, GetLastError());
			continue;
		}
		// Query the object type.
		while (! (objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000)));
		if (!NT_SUCCESS(NtQueryObject(
			dupHandle,
			ObjectTypeInformation,
			objectTypeInfo,
			0x1000,
			NULL))) {
			//printf("Could not get information about type in PID %d! GLE = %d.\n", handle_ProcessId, GetLastError());
			CloseHandle(processHandle);
			continue;
		}

		/*printf(
		"%llu\t %d\t %S\t [%#x]\t %.*S: (did not get name)\n",
		time(NULL),
		handle_ProcessId,
		current_process_name,
		handle.Handle,
		objectTypeInfo->Name.Length / 2,
		objectTypeInfo->Name.Buffer
		);*/

		if (wcscmp(objectTypeInfo->Name.Buffer, TEXT("Mutant"))) {
			//printf("Not Mutex.\n");
			free(objectTypeInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}

		while (!(objectNameInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000)));
		if (!NT_SUCCESS(NtQueryObject(
			dupHandle,
			ObjectNameInformation,
			objectNameInfo,
			0x1000,
			&returnLength
		))) {
			PVOID tmp_objectNameInfo;
			while(!(tmp_objectNameInfo = HeapReAlloc(GetProcessHeap, HEAP_ZERO_MEMORY, objectNameInfo, returnLength)));
			objectNameInfo = tmp_objectNameInfo;
			if (!NT_SUCCESS(NtQueryObject(
				dupHandle,
				ObjectNameInformation,
				objectNameInfo,
				returnLength,
				NULL
			))) {

				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				CloseHandle(processHandle);
				continue;
			}
		}

		objectName = *(PUNICODE_STRING)objectNameInfo;

		if (objectName.Length) {
			struct mutantInfo *mutant_item;
			DL_FOREACH(mutantsList, mutant_item) {
				if (wcsstr(objectName.Buffer, mutant_item->mutant_name)) {
					printf(
						"%llu\t %d\t %S\t [%#x]\t %.*S: %.*S\n",
						time(NULL),
						handle_ProcessId,
						current_process_name,
						handle.Handle,
						objectTypeInfo->Name.Length / 2,
						objectTypeInfo->Name.Buffer,
						objectName.Length / 2,
						objectName.Buffer
					);
					AddNewProcess(handle_ProcessId, mutant_item->hook, mutant_item->delay, mutant_item->network, mutant_item->dump, mutant_item->dumpInterval);
					break;
				}
			}
		}
		free(objectNameInfo);
		free(objectTypeInfo);
		CloseHandle(dupHandle);
		CloseHandle(processHandle);

	}

	free(handleInfo);

	return;
}

void _startMutantsMonitor() {
	while (TRUE) {
		FindMutantByName();
		Sleep(100);
	}
}

DWORD WINAPI startMutantsMonitor(std::thread **worker = nullptr)
{
	auto *myWorker = new std::thread(_startMutantsMonitor);
	if (worker != nullptr)
	{
		*worker = myWorker;
	}

	return 0;
}
