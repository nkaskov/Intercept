#include "stdafx.h"
#include "Global.h"
#include "tinyxml2.h"
#include "utlist.h"

struct processInfo *globalList;
struct processInfo *trashList;
struct mutantInfo *mutantsList;
WCHAR binaryPath[2 * MAX_PATH];
WCHAR dllPathX64[MAX_PATH];
WCHAR dllPathX86[MAX_PATH];
WCHAR interlayerPath[MAX_PATH];
WCHAR outputPath[2 * MAX_PATH];

CHAR networkInterface[128];

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
			const char *name = process->Attribute("name");
			if (name)
			{
				if (!MultiByteToWideChar(CP_ACP, 0, name, -1, item->processName, MAX_IMAGE))
				{
					HeapFree(GetProcessHeap(), 0x00, item);
					HeapFree(GetProcessHeap(), 0x00, mutant_item);
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
						return 1;
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