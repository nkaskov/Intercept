/*
*Every thread gets information about api-calls from connected analyzed processes using pipes
*And than send them to internal server.
*Internal server gets information about api-calls from all threads
*And than prints them all to output file
*/



#include "stdafx.h"
#include "Global.h"
#include "Queue.h"
#include "Utils.h"
#include "utlist.h"


#define BUFSIZE 5120
#define MAX_PIPES_FOR_SEGMENT 10 //Total number of analyzed processes.
//Is equal to total number of pipes, which are listening to information from analyzed processes

struct pipe_data {
	int pipe_number;
};
HANDLE hInternalPipe = INVALID_HANDLE_VALUE;
BOOL *pipes_states = NULL;

DWORD currently_number_of_segments = 0;


//---------------------Block for sending mesaages to internal server---------------------
//The main function of block is SendMessageToInternalServer

static DWORD ConnectToInternalServer() {


	BOOL   fSuccess = FALSE;
	DWORD dwMode;
	PWCHAR lpszPipeInternalName = TEXT("\\\\.\\pipe\\internal_pipe");

	while (TRUE)
	{
		hInternalPipe = CreateFile(
			lpszPipeInternalName,   // pipe name 
			GENERIC_WRITE,
			0,              // no sharing 
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe 
			0,              // default attributes 
			NULL);          // no template file 

							// Break if the pipe handle is valid. 

		if (hInternalPipe != INVALID_HANDLE_VALUE)
			break;

		// Exit if an error other than ERROR_PIPE_BUSY occurs. 

		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			_tprintf(TEXT("Could not open pipe. GLE=%d\n"), GetLastError());
			return -1;
		}


		if (!WaitNamedPipe(lpszPipeInternalName, 200))
		{
			_tprintf(TEXT("Could not open pipe: 200 msecond wait timed out.\n"));
			return -1;
		}
		Sleep(10);
	}

	dwMode = PIPE_READMODE_MESSAGE;
	fSuccess = SetNamedPipeHandleState(
		hInternalPipe,    // pipe handle 
		&dwMode,  // new pipe mode 
		NULL,     // don't set maximum bytes 
		NULL);    // don't set maximum time 
	if (!fSuccess)
	{
		_tprintf(TEXT("SetNamedPipeHandleState failed. GLE=%d\n"), GetLastError());
		return -1;
	}
	return 0;
}

static void ReConnectToInternalServer() {

	CloseHandle(hInternalPipe);
	while (ConnectToInternalServer()) {
		Sleep(100);
	}
}

void SendMessageToInternalServer(PWSTR cmd) {
	BOOL   fSuccess = FALSE;
	DWORD  cbToWrite, cbWritten;

	//wprintf(_T("%s %d\n"), cmd, wcslen(cmd));

	cbToWrite = (lstrlen(cmd) + 1) * sizeof(TCHAR);
	//wprintf(_T("Sending %d byte message: \"%s\"\n"), cbToWrite, cmd);

	fSuccess = WriteFile(
		hInternalPipe,                  // pipe handle 
		cmd,             // message 
		cbToWrite,              // message length 
		&cbWritten,             // bytes written 
		NULL);                  // not overlapped 

	if (!fSuccess)
	{
		_tprintf(TEXT("WriteFile to pipe failed. GLE=%d\n"), GetLastError());
		fflush(stdout);

		ReConnectToInternalServer();
		SendMessageToInternalServer(cmd);
	}
}


//---------------------Block of function CheckOnePipe---------------------
//CheckOnePipe gets messages with information about api-calls from one targeted process

//serviceCallback checks, is this message from input pipe a system message
static DWORD serviceCallback(PWCHAR cmd)
{
	size_t cmdLen = wcslen(cmd);
	if (cmdLen < 3)
	{
		return 1;
	}
	if (cmd[1] != '|') {
		return 1;
	}

	WCHAR c = cmd[0];
	switch (c) {
	case 'p': {
		DWORD processId;
		if (swscanf_s(cmd, L"p|%d", &processId) == 1) {
			struct processInfo *item;
			DL_FOREACH(globalList, item) {
				for (DWORD i = 0; i < item->pidCount; ++i) {
					if (item->pidList[i] == processId) {
						return 0;
					}
				}
			}

			item = (struct processInfo *)calloc(1, sizeof(struct processInfo));
			GetProcessName(processId, item->processName, MAX_IMAGE);

			item->running = TRUE;
			item->pidList[0] = processId;
			item->pidCount = 1;
			item->hook = TRUE;
			item->delay = DEFAULT_DELAY;
			item->network = TRUE;
			item->dump = TRUE;
			item->dumpInterval = DEFAULT_DUMPINTERVAL;

			_tprintf(TEXT("Adding new process %s with ProcessId %d\n"), item->processName, processId);

			DL_APPEND(globalList, item);
			return 0;
		}
		break;
	}
	default:
		return 1;
	}

}

//CheckOnePipe gets api-calls only from one targeted process
DWORD WINAPI CheckOnePipe(LPVOID lpvParam) {
	HANDLE hPipe = INVALID_HANDLE_VALUE;

	DWORD pipe_number = ((pipe_data *)lpvParam)->pipe_number;

	/*if (pipe_number >= MAX_PIPES_FOR_SEGMENT) {
	_tprintf(TEXT("Wrong pipe number: %d.\n"), pipe_number);
	fflush(stdout);
	return 1;
	}*/

	PWCHAR pipe_name = (PWCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 128 * sizeof(WCHAR));
	wsprintf(pipe_name, L"\\\\.\\pipe\\my_pipe_%d", pipe_number);

	while (TRUE) {
		if (hPipe != INVALID_HANDLE_VALUE) {
			Sleep(1000);
			continue;
		}

		hPipe = CreateFile(
			pipe_name,
			GENERIC_READ, // only need read access
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL
		);

		if (hPipe == INVALID_HANDLE_VALUE) {
			//wprintf(L"Could not open pipe %s. GLE = %d.\n", pipe_name, GetLastError());
			//DeleteFile(current_pipe_name);
			Sleep(10);
			continue;
		}


		//else CloseHandle(tmp_hThread);
		//wprintf(L"Connected to pipe %s\n", pipe_name);

		wchar_t buffer[BUFSIZE];
		BOOL was_connected = FALSE;

		while (TRUE) {
			DWORD numBytesRead = 0;
			BOOL result = ReadFile(
				hPipe,
				buffer, // the data from the pipe will be put here
				(BUFSIZE - 1) * sizeof(wchar_t), // number of bytes allocated
				&numBytesRead, // this will store number of bytes actually read
				NULL // not using overlapped IO
			);

			if (result) {
				buffer[numBytesRead / sizeof(wchar_t)] = '\0'; // null terminate the string
															   //wcout << "Number of bytes read: " << numBytesRead << "From " << pipe_name << endl;
															   //wcout << "Message: " << buffer << endl;
				if (!was_connected) {
					was_connected = TRUE;
					_tprintf(TEXT("Connected to pipe %s.\n"), pipe_name);
					fflush(stdout);
				}
				pipes_states[pipe_number] = TRUE;

				wprintf(L"INCOME message: \n%s\n", buffer);

				if (wcscmp(L"CONNECT", buffer)) {
					if (serviceCallback(buffer)) {

						SendMessageToInternalServer(buffer);
					}

				}
			}
			else {
				DWORD error = GetLastError();
				//if ((error != ERROR_PIPE_NOT_CONNECTED) && (error != ERROR_BROKEN_PIPE)) {
				_tprintf(TEXT("Failed to read data from the pipe %s GLE = %d.\n"), pipe_name, error);
				fflush(stdout);
				//}
				pipes_states[pipe_number] = FALSE;

				if (was_connected) {
					_tprintf(TEXT("Disconnected from pipe %s.\n"), pipe_name);
					fflush(stdout);
				}
				//_tprintf(TEXT("Some another error while read. GLE = %d"), GetLastError());
				//fflush(stdout);
				break;
			}
		}


		FlushFileBuffers(hPipe);
		DisconnectNamedPipe(hPipe);
		CloseHandle(hPipe);

		hPipe = INVALID_HANDLE_VALUE;

	}
	return 0;
}



//---------------------Main function of internal server---------------------
//Thread function for writing to output file:
//Input: API-calls (from threads);
//Output: write all API-calls to output file.
DWORD WINAPI PrintPipesResult(LPVOID lpvParam) {

	BOOL   fConnected = FALSE, fSuccess = FALSE;
	LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\internal_pipe");
	HANDLE hPipe = INVALID_HANDLE_VALUE;


	TCHAR* pchRequest = (TCHAR*)HeapAlloc(GetProcessHeap(), 0, BUFSIZE * sizeof(TCHAR));

	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;

	hPipe = CreateNamedPipe(
		lpszPipename,             // pipe name 
		PIPE_ACCESS_DUPLEX,       // read/write access 
		PIPE_TYPE_MESSAGE |       // message type pipe 
		PIPE_READMODE_MESSAGE |   // message-read mode 
		PIPE_WAIT,                // blocking mode 
		PIPE_UNLIMITED_INSTANCES, // max. instances  
		BUFSIZE,                  // output buffer size 
		BUFSIZE,                  // input buffer size 
		0,                        // client time-out 
		NULL);                    // default security attribute 

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("CreateNamedPipe failed, GLE=%d.\n"), GetLastError());
		return -1;
	}

	fConnected = ConnectNamedPipe(hPipe, NULL) ?
		TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

	if (fConnected)
	{
		FILE *f;

		WCHAR output[MAX_PATH];
		PathCombine(output, outputPath, L"output.dw");

		while (!(f = _wfopen(output, L"a, ccs=UTF-8")));

		fwprintf(f, L"Timestamp|Module|ProcessId|Action|Arguments|Result|GetLastError\n");

		while (TRUE) {
			// Read client requests from the pipe. This simplistic code only allows messages
			// up to BUFSIZE characters in length.
			fSuccess = ReadFile(
				hPipe,        // handle to pipe 
				pchRequest,    // buffer to receive data 
				BUFSIZE * sizeof(TCHAR), // size of buffer 
				&cbBytesRead, // number of bytes read 
				NULL);        // not overlapped I/O 

			if (!fSuccess || cbBytesRead == 0) {
				if (GetLastError() == ERROR_BROKEN_PIPE) {
					_tprintf(TEXT("InstanceThread ReadFile failed, GLE=%d.\n"), GetLastError());
					//fflush(stdout);
				}
				break;
			}
			//_tprintf(TEXT("Client Request String:\"%s\"\n"), pchRequest);
			//fflush(stdout);
			//fwprintf(f, L"%s\n", (PWCHAR)pchRequest);

			int iter = 0;
			int previter = 0;
			while (pchRequest[iter]) {
				while (pchRequest[iter] != '\n') {
					++iter;
				}
				//Ll;
				unsigned long long ts = time(NULL);
				fwprintf(f, L"%llu|%.*s\n", ts, iter - previter, (PWCHAR)pchRequest + previter);
				wprintf(L"%llu|%.*s\n", ts, iter - previter, (PWCHAR)pchRequest + previter);
				iter++;
				previter = iter;
			}

			fflush(f);
			Sleep(100);
		}

		FlushFileBuffers(hPipe);
		DisconnectNamedPipe(hPipe);
		CloseHandle(hPipe);
		fclose(f);
		HeapFree(GetProcessHeap(), 0, pchRequest);
	}
	else {
		CloseHandle(hPipe);
		HeapFree(GetProcessHeap(), 0, pchRequest);
	}

}


//---------------------Start monitoring all targeted processes---------------------


//Returns number currently connected clients
DWORD GetNumberOfCurrentlyConnectedPipes() {
	DWORD result = 0;
	for (DWORD i = 0; i < currently_number_of_segments * MAX_PIPES_FOR_SEGMENT; ++i) {
		result += pipes_states[i] ? 1 : 0;
	}
	if (result) {
		static DWORD attempt = 0;
		if (!attempt % 10) { _tprintf(TEXT("Currently connected pipes: %d from %d.\n"), result, currently_number_of_segments * MAX_PIPES_FOR_SEGMENT); }
		attempt += 1;
	}
	return result;
}

//Start thread, which writes output to file,
// and threads, which listen to the messages from processes
void _startMonitorQueue() {
	struct pipe_data * pipe_input_data = NULL;
	HANDLE *hPipes = NULL;
	DWORD * dwThreadIds = NULL;
	HANDLE internal_server_handle = INVALID_HANDLE_VALUE;
	DWORD internal_server_id = 0;

	currently_number_of_segments = 1;

	pipes_states = (BOOL *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PIPES_FOR_SEGMENT * currently_number_of_segments * sizeof(BOOL));
	dwThreadIds = (DWORD *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PIPES_FOR_SEGMENT * currently_number_of_segments * sizeof(DWORD));
	hPipes = (HANDLE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PIPES_FOR_SEGMENT * currently_number_of_segments * sizeof(HANDLE));
	pipe_input_data = (struct pipe_data *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PIPES_FOR_SEGMENT * currently_number_of_segments * sizeof(struct pipe_data));

	internal_server_handle = CreateThread(
		NULL,              // no security attribute 
		0,                 // default stack size 
		PrintPipesResult,    // thread proc
		NULL,    // thread parameter 
		0,                 // not suspended 
		&internal_server_id);     // returns thread ID

	Sleep(10);
	while (ConnectToInternalServer());


	for (DWORD current_pipe_number = 0; current_pipe_number < currently_number_of_segments * MAX_PIPES_FOR_SEGMENT; current_pipe_number++) {
		pipe_input_data[current_pipe_number].pipe_number = current_pipe_number;

		hPipes[current_pipe_number] = CreateThread(
			NULL,              // no security attribute 
			0,                 // default stack size 
			CheckOnePipe,    // thread proc
			(LPVOID)&(pipe_input_data[current_pipe_number]),    // thread parameter 
			0,                 // not suspended 
			&dwThreadIds[current_pipe_number]);     // returns thread ID 
	}

	while (TRUE) {

		if (GetNumberOfCurrentlyConnectedPipes() >= currently_number_of_segments * MAX_PIPES_FOR_SEGMENT - MAX_PIPES_FOR_SEGMENT / 2) {
			currently_number_of_segments += 1;
			pipes_states = (BOOL *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pipes_states, MAX_PIPES_FOR_SEGMENT * currently_number_of_segments * sizeof(BOOL));
			dwThreadIds = (DWORD *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwThreadIds, MAX_PIPES_FOR_SEGMENT * currently_number_of_segments * sizeof(DWORD));
			hPipes = (HANDLE *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hPipes, MAX_PIPES_FOR_SEGMENT * currently_number_of_segments * sizeof(HANDLE));
			pipe_input_data = (struct pipe_data *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pipe_input_data, MAX_PIPES_FOR_SEGMENT * currently_number_of_segments * sizeof(struct pipe_data));

			for (DWORD current_pipe_number = (currently_number_of_segments - 1) * MAX_PIPES_FOR_SEGMENT; current_pipe_number < currently_number_of_segments * MAX_PIPES_FOR_SEGMENT; current_pipe_number++) {
				pipe_input_data[current_pipe_number].pipe_number = current_pipe_number;

				hPipes[current_pipe_number] = CreateThread(
					NULL,              // no security attribute 
					0,                 // default stack size 
					CheckOnePipe,    // thread proc
					(LPVOID)&(pipe_input_data[current_pipe_number]),    // thread parameter 
					0,                 // not suspended 
					&dwThreadIds[current_pipe_number]);     // returns thread ID 
			}
		}
		Sleep(100);
	}

}

DWORD WINAPI startMonitorQueue(std::thread **worker = nullptr)
{
	auto *myWorker = new std::thread(_startMonitorQueue);
	if (worker != nullptr)
	{
		*worker = myWorker;
	}

	return 0;
}
