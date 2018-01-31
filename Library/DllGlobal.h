#pragma once

#include "stdafx.h"

extern WCHAR moduleName[MAX_PATH + 1];
extern DWORD processId;

typedef LONG NTSTATUS;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

typedef DWORD(__stdcall *NtQueryKeyType)(HANDLE KeyHandle,
	int KeyInformationClass,
	PVOID KeyInformation,
	ULONG Length,
	PULONG ResultLength);

extern NtQueryKeyType NtQueryKey;

void SendMessageToMonitorServer(PWCHAR);