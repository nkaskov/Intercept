#pragma once

#include "stdafx.h"
//#include <thread>

#include "Global.h"
#include "Utils.h"
#include "utlist.h"
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <sstream>
#include <map>
#include <vector>
#include "tchar.h"



DWORD WINAPI startFileRequestsMonitor(std::thread **worker);