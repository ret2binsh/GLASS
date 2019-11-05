// timestomp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>

#define fs 

BOOL FileTime(char* FileName, FILETIME *ftCreate, FILETIME *ftAccess, FILETIME *ftWrite, BOOL timestomp);
BOOL TimeStomp(char* FileName, FILETIME* ftCreate, FILETIME* ftAccess, FILETIME* ftWrite);
void usage(char* prog);

int main(int argc, char **argv)
{
	BOOL timestomp = FALSE;
	BOOL success = FALSE;
	FILETIME ftCreate, ftAccess, ftWrite;

	if (argc < 2)
		usage(argv[0]);

	if (argc == 2)
	{
		FileTime(argv[1], &ftCreate, &ftAccess, &ftWrite, timestomp);
		return 0;
	}

	if (argc > 2)
	{
		timestomp = TRUE;
		success = FileTime(argv[2], &ftCreate, &ftAccess, &ftWrite, timestomp);
		if (success)
			TimeStomp(argv[1], &ftCreate, &ftAccess, &ftWrite);
	}

	return 0;
}

BOOL
FileTime(char* FileName, FILETIME* ftCreate, FILETIME* ftAccess, FILETIME* ftWrite, BOOL timestomp)
{
	HANDLE hFile;
	SYSTEMTIME stUTC, stLocal;
	TCHAR lpBuff[MAX_PATH];
	wchar_t buf[256];
	
	hFile = CreateFileA(FileName, FILE_READ_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);
	
	if (hFile == NULL || hFile < 0)
	{
		FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, GetLastError(), 0, buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
		wprintf(L"%s\n", buf);
		return FALSE;
	}

	if (!GetFileTime(hFile, ftCreate, ftAccess, ftWrite))
	{
		FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, GetLastError(), 0, buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
		wprintf(L"%s\n", buf);
		CloseHandle(hFile);
		return FALSE;
	}
	CloseHandle(hFile);

	if (timestomp)
		return TRUE;

	FileTimeToSystemTime(ftCreate, &stUTC);
	SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

	StringCchPrintf(lpBuff, MAX_PATH,
		TEXT("%02d/%02d/%d  %02d:%02d"),
		stLocal.wMonth, stLocal.wDay, stLocal.wYear,
		stLocal.wHour, stLocal.wMinute);

	_tprintf(TEXT("Create time: %-10s\n"), lpBuff);

	FileTimeToSystemTime(ftAccess, &stUTC);
	SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

	StringCchPrintf(lpBuff, MAX_PATH,
		TEXT("%02d/%02d/%d  %02d:%02d"),
		stLocal.wMonth, stLocal.wDay, stLocal.wYear,
		stLocal.wHour, stLocal.wMinute);

	_tprintf(TEXT("Access time: %-10s\n"), lpBuff);

	FileTimeToSystemTime(ftWrite, &stUTC);
	SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

	StringCchPrintf(lpBuff, MAX_PATH,
		TEXT("%02d/%02d/%d  %02d:%02d"),
		stLocal.wMonth, stLocal.wDay, stLocal.wYear,
		stLocal.wHour, stLocal.wMinute);

	_tprintf(TEXT("Write  time: %-10s\n"), lpBuff);

	return TRUE;
}

BOOL
TimeStomp(char* fileName, FILETIME* ftCreate, FILETIME* ftAccess, FILETIME* ftWrite)
{

	HANDLE hFile;
	wchar_t buf[256];

	hFile = CreateFileA(fileName, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == NULL || hFile < 0)
	{
		FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, GetLastError(), 0, buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
		wprintf(L"%s\n", buf);
		return FALSE;
	}

	if (!SetFileTime(hFile, ftCreate, ftAccess, ftWrite))
	{
		FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, GetLastError(), 0, buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
		wprintf(L"%s\n", buf);
		return FALSE;
	}
	printf("Successfully set time.\n");
	CloseHandle(hFile);

	return TRUE;

}

void
usage(char* prog)
{
	printf("Usage: %s [ -h ] TARGETFILE [ REFERENCEFILE ]\n\n",(char*)prog);
	printf("Required Arguments:\n");
	printf("%-30s %-10s\n\n", "TARGETFILE","Target file to Timestomp. By itself will display current timestamp.");
	printf("Optional Arguments:\n");
	printf("%-30s %-10s\n", "-h", "This help menu");
	printf("%-30s %-10s\n", "REFERENCEFILE", "File to reference for Timestomping the TARGETFILE.");
	exit(0);

}
