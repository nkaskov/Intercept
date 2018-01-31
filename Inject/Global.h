#pragma once

#include "stdafx.h"

int initGlobal();

#define MAX_PID_COUNT 64
#define MAX_IMAGE 256

#define DEFAULT_DELAY 2
#define DEFAULT_DUMPINTERVAL 120

struct processInfo {
	WCHAR processName[MAX_IMAGE];

	DWORD pidList[MAX_PID_COUNT];
	DWORD pidCount;

	BOOL running;
	BOOL persistent;

	BOOL hook;
	DWORD delay;

	BOOL network;

	BOOL dump;
	DWORD dumpInterval;
	ULONGLONG dumpTime;
	ULONGLONG dumpId;

	struct processInfo *prev;
	struct processInfo *next;
};
struct mutantInfo {
	WCHAR mutant_name[256];
	DWORD delay;
	BOOL hook;
	BOOL network;
	BOOL dump;
	DWORD dumpInterval;
	BOOL persistent;
	struct mutantInfo* prev;
	struct mutantInfo* next;
};

extern struct processInfo *globalList;
extern struct processInfo *trashList;
extern struct mutantInfo *mutantsList;

extern WCHAR binaryPath[];
extern WCHAR dllPathX64[];
extern WCHAR dllPathX86[];
extern WCHAR interlayerPath[];
extern WCHAR outputPath[];
extern CHAR networkInterface[];