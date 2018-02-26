
#include "Utils.h"

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

	_tprintf(TEXT("Adding new process %s with ProcessId %u\n"), item->processName, processId);

	DL_APPEND(globalList, item);
	return 0;
}