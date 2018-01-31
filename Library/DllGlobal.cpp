#include "stdafx.h"

#include "DllGlobal.h"

WCHAR moduleName[MAX_PATH + 1];
DWORD processId;

HANDLE hMonitorQueue = NULL;
HANDLE hServiceQueue = NULL;


NtQueryKeyType NtQueryKey = NULL;
