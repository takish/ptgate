/*
 * $Date: 2005/01/25 11:57:52 $
 * $Id: session.h,v 1.14 2005/01/25 11:57:52 takashi Exp $
 * $Revision: 1.14 $
 */
#ifndef _session_h
#define _session_h

#include "includes.h"

typedef struct sc_addr {
		char *addr;
		char *port;
} sc_addr_t;

typedef struct s_session {
#if 1
	sc_addr_t ESendAddr[5];
	sc_addr_t EServAddr;
//	sc_addr_t DSendAddr[5];
	sc_addr_t DSendAddr;
	sc_addr_t DServAddr;
	sc_addr_t RSendAddr[5];
#endif
#if 0
	struct sockaddr_in ESendAddr[3];
	struct sockaddr_in EServAddr;
	struct sockaddr_in DSendAddr[3];
	struct sockaddr_in DServAddr;
#endif
	int	session_num;
	int	relay_num;
	char *send_group_e;
	char *serv_group_e;
	char *send_group_d;
	char *serv_group_d;
	void *rs_handle;
	int b_size;
	int through;
//    char *hostip;
    int hostip;
    u_char mac[6];
    int netmask;
    int network;
    int destnet;
    int destmask;
//    char *localnet;
//    char *hostip6;
    int  enable_ipv6;
    char hostip6[44];
    int prefix;
    double lossrate;
    char m_taddr[5];
    char m_taddr6[44];
	int	d_port_cnt;
    int d_port[5];
} session_t;

/* thread struct */
typedef struct ThreadArgs{
#if 0
//	struct sockaddr_in CTL_Serv_Addr; /* encode RTCP server address */
//	struct sockaddr_in CTL_Send_Addr; /* encode RTCP send address */
//	struct sockaddr_in CTL_Addr; /* encode RTCP send address */
#endif
	sc_addr_t CTL_Serv_Addr; /* encode RTCP server address */
	sc_addr_t CTL_Send_Addr; /* encode RTCP send address */
	sc_addr_t CTL_Addr; /* encode RTCP send address */
	char *send_group_e;
	char *serv_group_e;
	char *send_group_d;
	char *serv_group_d;
} th_args_t;

void session_init(session_t *sp);
#endif /* _session_h_ */
