#include "socket.h"
#include "includes.h"

#include<stdio.h>
#include<sys/types.h>
#include <sys/time.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<sys/wait.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>

/* 送信用UNSPECソケット */
int send_sock_create(const char *host, const char *port, void ** saptr, 
socklen_t *lenp)
{
    int sofd, n;
    char s_port[80];
    struct addrinfo hints, *res, *ressave;
  
    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if((n = getaddrinfo(host, port, &hints, &res)) != 0)
    {
        fprintf(stderr,"error_getaddrinfo %s %s %s\n", host, port, 
        gai_strerror(n));
        exit(1);
    }
    ressave = res;
  
    do {
        sofd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if(sofd >= 0)
        {
            break;
        }
    } while((res = res->ai_next) != NULL);
  
    if(res == NULL)
    {
        fprintf(stderr,"send sock error for %s %s\n", host, port);
    }

    *saptr = (struct ai_addrlen *)malloc(res->ai_addrlen);
    memcpy(*saptr, res->ai_addr, res->ai_addrlen);
    *lenp = res->ai_addrlen;
  
    freeaddrinfo(ressave);
    return(sofd);
}

/* 受信用UNSPECソケット */
int recv_sock_create(const char *host, const char *port, socklen_t *addrlenp)
{
    int sofd, n;
    char d_port[80];
    struct addrinfo hints, *res, *ressave;
    struct addrinfo *ai;
  
//    ai = host_serv(host, NULL, 0, 0);
//    printf("%s\n", host);
//    printf("%s\n", ai->ai_family);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
  
    if((n = getaddrinfo(host, port, &hints, &res)) != 0)
    {
        fprintf(stderr,"error_getaddrinfo %s %s %s\n", host, port, gai_strerror(n));
        exit(1);
        /* NOTREACHED */
    }

    ressave = res;

    do {
        sofd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if(sofd < 0)
        {
            continue;
        }
        if(bind(sofd, res->ai_addr, res->ai_addrlen) == 0)
        {
            break;
        }
    
        close(sofd);
    }while((res = res->ai_next) != NULL);
  
    if(res == NULL)
    {
        fprintf(stderr,"recv sock error for %s %s\n", host, port);
        exit(1);
    }

    if(addrlenp)
    {
        *addrlenp = res->ai_addrlen;
    }

    freeaddrinfo(ressave);
    return(sofd);
}

const SA *
gai(const char *hostname, const char *port){
    struct addrinfo hints, *res, *res0;
    static struct sockaddr_storage ss;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    error = getaddrinfo(hostname, port, &hints, &res);

    if(error){
        fprintf(stderr,"error_getaddrinfo %s %s %s\n", 
                    hostname, port, gai_strerror(error));
        exit(1);
        /* NOTREACHED */
    }

    if (res->ai_addrlen > sizeof(ss)){
        fprintf(stderr, "sockaddr too large\n");
        exit(1);
        /* NOTREACHED */
    }

    memcpy(&ss, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);
                
    return (const SA *)&ss;
}

/* 送信用RAWソケット(IPv4) */
int send_raw_sock_create(void)
{
    int ssock;    
    int on = 1;

    if((ssock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) == -1){
            perror("send_raw_sock_create");
            exit(1);
    }

    if(setsockopt(ssock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
            perror("setsockopt");
            exit(1);
    }
    
    return ssock;
}

/* 送信用RAWソケット(IPv6) */
int send_raw_sock6_create(void)
{
    int ssock;    
    int on = 1;

    if((ssock = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW)) == -1){
            perror("send_raw_sock6_create");
            exit(1);
    }

    return ssock;
}

/* 受信用RAWソケット */
int raw_sock_create(char *interface, int promisc_flag)
{
    int rsock;
    struct ifreq ifr;
    struct packet_mreq mreq;
    struct sockaddr_in *sin;
    struct sockaddr_in netmask;
    struct sockaddr_ll sll;
                                                                                
    if ((rsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0 ){
        perror("raw sock create");
        exit(0);
    }
                                                                                
    strcpy(ifr.ifr_name, interface);
                                                                                
    if(ioctl(rsock, SIOCGIFINDEX, &ifr) < 0 ){
        perror("ioct SIOCGIFINDEX");
        close(rsock);
        exit(0);
    }

    if(promisc_flag){
        mreq.mr_type = PACKET_MR_PROMISC;
        mreq.mr_ifindex = ifr.ifr_ifindex;
        mreq.mr_alen = 0;
        mreq.mr_address[0] ='\0';
                                                                                
        if( (setsockopt(rsock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq))) < 0){
            perror("setsockopt");
            close(rsock);
            exit(0);
        }
    }

    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;

    if( bind(rsock, (SA *)&sll, sizeof(sll)) < 0) {
        perror("raw sock bind");
        close(rsock);
        exit(0);
    }

//    getifaddr(ifr.ifr_name);
//    getifmask(ifr.ifr_name);
/*    ioctl(rsock, SIOCGIFFLAGS, &ifr);
    if(ifr.ifr_flags&IFF_RUNNING){
        printf(" RUN OK \n");
    } else {
        printf(" Please Check eth0\n");
    }

    ioctl(rsock, SIOCGIFADDR, &ifr);
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    printf("name %s IP %s\n",ifr.ifr_name, inet_ntoa(sin->sin_addr));

    if(ioctl(rsock, SIOCGIFNETMASK, (caddr_t)&ifr)<0){
        perror("SIOCGIMETRIC");
        exit(0);
    }

    netmask.sin_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    printf("netmask 0x%x \n", ntohl(netmask.sin_addr.s_addr));
*/                                                                                
    return rsock;
}

#if 0
void recover_from_promisc(int sock, char *interface){
    struct ifreq if_req;
    strcpy(if_req.ifr_name, interface);
    if_req.ifr_flags = if_req.ifr_flags & ~IFF_PROMISC;

    if(ioctl(sock,SIOCGIFFLAGS,&if_req) < 0 ){
        perror("ioctl error");
        close(sock);
        exit(1);
    }
}
#endif

/* インターフェースをプロミスキャスモードから戻す */
void recover_from_promisc(char *interface){
    struct ifreq ifr;
    int sock;

    sock = socket(PF_INET, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, interface);
    ifr.ifr_flags = ifr.ifr_flags & ~IFF_PROMISC;

    if(ioctl(sock,SIOCGIFFLAGS,&ifr) < 0 ){
        perror("ioctl error");
        close(sock);
        exit(1);
    }
}

/* インターフェスからIPアドレスを取得 */
char *getifaddr(char *interface){
    struct ifreq ifr;
    struct sockaddr_in *sin;
    int sock;
    char addr[20];
    char *paddr;

    sock = socket(PF_INET, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFADDR, &ifr);
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
//    printf("IP %s\n",inet_ntoa(sin->sin_addr));
//    printf("IP %x\n",ntohl(sin->sin_addr.s_addr));

    sprintf(addr,"%s",inet_ntoa(sin->sin_addr));
    paddr = addr;
    /* アドレスをstringで返す */
    return paddr;
}

/* インターフェスからIPアドレスを16進数で取得 */
int getifhexaddr(char *interface){
    struct ifreq ifr;
    struct sockaddr_in *sin;
    int sock;
    int addr;

    sock = socket(PF_INET, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFADDR, &ifr);
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
//    printf("IP %x\n",ntohl(sin->sin_addr.s_addr));

    /* アドレスを16進数で返す */
    return ntohl(sin->sin_addr.s_addr);
}

/* インターフェースからネットマスクを取得 */
int getifmask(char *interface){
    struct ifreq ifr;
    struct sockaddr_in netmask;
    int sock;
//    char mask[20];
//    u_int32_t mask;
    int mask;
//    char *pmask;

    sock = socket(PF_INET, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, interface);
    if(ioctl(sock, SIOCGIFNETMASK, (caddr_t)&ifr)<0){
        perror("SIOCGIMETRIC");
        exit(0);
    }

    netmask.sin_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
//    sprintf(mask, "%x", ntohl(netmask.sin_addr.s_addr));
//    printf("netmask 0x%x \n", ntohl(netmask.sin_addr.s_addr));

    return ntohl(netmask.sin_addr.s_addr);
//    pmask = mask;
//    return pmask;
}

int getifhwaddr(char *interface, unsigned char mac[]){
    struct ifreq ifr;
    int sock;

    sock = socket(PF_INET, SOCK_DGRAM, 0);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    ioctl(sock, SIOCGIFHWADDR, &ifr);

/*    printf("HW %2.2x",ifr.ifr_hwaddr.sa_data[0]);
    printf("%2.2x",ifr.ifr_hwaddr.sa_data[1]);
    printf("%2.2x",ifr.ifr_hwaddr.sa_data[2]);
    printf("%2.2x",ifr.ifr_hwaddr.sa_data[3]);
    printf("%2.2x",(ifr.ifr_hwaddr.sa_data[4]&0xff));
    printf("%2.2x\n",(ifr.ifr_hwaddr.sa_data[5]&0xff));
*/

    close(sock);

    /* アドレスを16進数で返す */
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

int getifrun(char *interface){
    struct ifreq ifr;
    int sock;

    sock = socket(PF_INET, SOCK_DGRAM, 0);

    ioctl(sock, SIOCGIFFLAGS, &ifr);

    printf("%4x\n", ifr.ifr_flags);

    if(ifr.ifr_flags&IFF_UP){
        puts("UP");
    } else {
        puts("DOWN");
    }
    if(ifr.ifr_flags&IFF_RUNNING){
        puts("RUN");
    } else {
        puts("DOWN");
    }

    if(ifr.ifr_flags&IFF_RUNNING){
        return 0;
    } else {
        return 1;
    }
}

char *inet_ntoa_ex(int netaddr){
    struct sockaddr_in *sin;
    char addr[20];
    char *paddr;

    sin->sin_addr.s_addr = (netaddr);
//    printf("IP %s\n",inet_ntoa(sin->sin_addr));
//    printf("IP %x\n",ntohl(sin->sin_addr.s_addr));

    sprintf(addr,"%s",inet_ntoa(sin->sin_addr));
    paddr = addr;
    return paddr;
}
