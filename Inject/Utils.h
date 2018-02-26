#pragma once

#include "stdafx.h"
#include "stdafx.h"
#include <thread>
#include "Global.h"
#include "utlist.h"
#include "Psapi.h"

DWORD GetProcessName(DWORD, LPWSTR, DWORD);
DWORD AddNewProcess(DWORD, BOOL, DWORD, BOOL, BOOL, DWORD);
