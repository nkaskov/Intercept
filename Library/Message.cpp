#include "stdafx.h"

#include "mq.h"

#pragma comment(lib,"mqrt.lib")

HRESULT QueueInitialize(
	WCHAR * wszQueueName,
	WCHAR * wszComputerName,
	HANDLE * hQueue
)
{
	// Validate the input strings.  
	if (wszQueueName == NULL || wszComputerName == NULL)
	{
		return MQ_ERROR_INVALID_PARAMETER;
	}

	HRESULT hr = MQ_OK;                                 // Return code

	// Create a direct format name for the queue.  
	WCHAR * wszFormatName = NULL;
	DWORD dwBufferLength = 0;
	const WCHAR * wszFormatStr = L"DIRECT=OS:%s\\%s";
	dwBufferLength = wcslen(wszQueueName) + wcslen(wszComputerName) +
		wcslen(wszFormatStr) - 4 + 1;

	wszFormatName = new WCHAR[dwBufferLength];
	if (wszFormatName == NULL)
	{
		return MQ_ERROR_INSUFFICIENT_RESOURCES;
	}
	memset(wszFormatName, 0, dwBufferLength * sizeof(WCHAR));

	if (_snwprintf_s(
		wszFormatName,
		dwBufferLength,
		dwBufferLength - 1,
		L"DIRECT=OS:%s\\%s",
		wszComputerName,
		wszQueueName
	) < 0)
	{
		wprintf(L"The format name is too long for the buffer specified.\n");
		return FALSE;
	}
	else
	{
		wszFormatName[dwBufferLength - 1] = L'\0';
	}

	// Call MQOpenQueue to open the queue with send access.  
	hr = MQOpenQueue(
		wszFormatName,                     // Format name of the queue  
		MQ_SEND_ACCESS,                    // Access mode  
		MQ_DENY_NONE,                      // Share mode  
		hQueue                            // OUT: Queue handle  
	);
	// Free the memory that was allocated for the format name string.  
	delete[] wszFormatName;

	// Handle any error returned by MQOpenQueue.  
	if (FAILED(hr))
	{
		wprintf(L"QueueInitialize: MQOpenQueue failed with code 0x%08x\n", hr);
		return hr;
	}
	
	return hr;
}

HRESULT QueueSendMessage(
	HANDLE hQueue,
	WCHAR * wszLabel
)
{
	
	// Define the required constants and variables.  
	const int NUMBEROFPROPERTIES = 5;                   // Number of properties  
	DWORD cPropId = 0;                                  // Property counter  
	HRESULT hr = MQ_OK;                                 // Return code  

														// Define an MQMSGPROPS structure.  
	MQMSGPROPS msgProps;
	MSGPROPID aMsgPropId[NUMBEROFPROPERTIES];
	MQPROPVARIANT aMsgPropVar[NUMBEROFPROPERTIES];
	HRESULT aMsgStatus[NUMBEROFPROPERTIES];

	// Specify the message properties to be sent.  
	aMsgPropId[cPropId] = PROPID_M_LABEL;               // Property ID  
	aMsgPropVar[cPropId].vt = VT_LPWSTR;                // Type indicator  
	aMsgPropVar[cPropId].pwszVal = wszLabel;            // The message label  
	cPropId++;

	// Initialize the MQMSGPROPS structure.  
	msgProps.cProp = cPropId;
	msgProps.aPropID = aMsgPropId;
	msgProps.aPropVar = aMsgPropVar;
	msgProps.aStatus = aMsgStatus;
	
	// Call MQSendMessage to send the message to the queue.  
	
	hr = MQSendMessage(
		hQueue,                          // Queue handle  
		&msgProps,                       // Message property structure  
		MQ_NO_TRANSACTION               // Not in a transaction  
	);
	if (FAILED(hr))
	{
		wprintf(L"SendMessage: MQSendMessage failed with code 0x%08x\n", hr);
		MQCloseQueue(hQueue);
		return hr;
	}
	
	return hr;
}

HRESULT QueueClose(HANDLE hQueue)
{
	HRESULT hr = MQCloseQueue(hQueue);
	return hr;
}
