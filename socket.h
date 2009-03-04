#ifndef _socket_h_
#define _socket_h_

#include <netdb.h>

int send_sock_create(const char *host, const char *serv, 
		     void ** saptr, socklen_t *lenp);
int recv_sock_create(const char *host, const char *serv, 
		     socklen_t *addrlenp);
const struct sockaddr * gai(const char *hostname, const char *port);
//void recover_from_promisc(int socket, char *interface);
void recover_from_promisc(char *interface);
char *getifaddr(char *interface);
int getifhexaddr(char *interface);
int getifmask(char *interface);
char *inet_ntoa_ex(int addr);

#endif
