#pragma once
#include "stdafx.h"

HRESULT QueueInitialize(WCHAR * wszQueueName, WCHAR * wszComputerName, HANDLE * hQueue);
HRESULT QueueSendMessage(HANDLE hQueue, WCHAR * wszLabel);
HRESULT QueueClose(HANDLE hQueue);
