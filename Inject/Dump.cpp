#include "stdafx.h"
#include "Global.h"
#include "utlist.h"

#include <thread>

#include "ProcessDump.h"
/*#if defined _M_X64
#pragma comment(lib, "ProcessDump-x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "ProcessDump-x86.lib")
#endif*/

void startDump(void)
{
	WCHAR dirName[260];
	WCHAR path[MAX_PATH];

	ULONGLONG ts;
	struct processInfo *process;

	while (TRUE)
	{
		DL_FOREACH(globalList, process)
		{
			ts = (ULONGLONG)time(NULL);

			if (!process->running || !process->dump || ts - process->dumpTime < process->dumpInterval)
			{
				continue;
			}
			if (process->persistent)
			{
				wsprintf(dirName, L"%s_%d", process->processName, process->dumpId);
				PathCombine(path, outputPath, dirName);
				if (CreateDirectory(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
				{
					ProcessDumpByName(process->processName, path);
				}
				++process->dumpId;
			}
			else
			{
				for (int i = 0; i < process->pidCount; ++i)
				{
					wsprintf(dirName, L"%s_%04X_%d", process->processName, process->pidList[i], process->dumpId);
					PathCombine(path, outputPath, dirName);
					if (CreateDirectory(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
					{
						ProcessDumpById(process->pidList[i], path);
					}
				}
				++process->dumpId;
			}

			process->dumpTime = ts;
		}
		DL_FOREACH(trashList, process)
		{
			ts = (ULONGLONG)time(NULL);

			if (!process->running || !process->dump || ts - process->dumpTime < process->dumpInterval)
			{
				continue;
			}
			if (process->persistent)
			{
				wsprintf(dirName, L"%s_%d", process->processName, process->dumpId);
				PathCombine(path, outputPath, dirName);
				if (CreateDirectory(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
				{
					ProcessDumpByName(process->processName, path);
				}
				++process->dumpId;
			}
			else
			{
				for (int i = 0; i < process->pidCount; ++i)
				{
					wsprintf(dirName, L"%s_%04X_%d", process->processName, process->pidList[i], process->dumpId);
					PathCombine(path, outputPath, dirName);
					if (CreateDirectory(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
					{
						ProcessDumpById(process->pidList[i], path);
					}
				}
				++process->dumpId;
			}

			process->dumpTime = ts;
		}
		Sleep(100);
	}
}

int initDump()
{
	auto *monitorWorker = new std::thread(startDump);

	return 0;
}
