#pragma once

#include "stdafx.h"
#include <thread>
#include "utlist.h"
#include "Global.h"
#include "Utils.h"

DWORD WINAPI startMutantsMonitor(std::thread **worker);