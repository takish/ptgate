/*
 * $Date: 2005/01/25 11:57:52 $
 * $Id: includes.h,v 1.31 2005/01/25 11:57:52 takashi Exp $
 * $Revision: 1.31 $
 */
#ifndef _includes_h
#define _includes_h

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <assert.h>

#include "rs.h"
#include "char.h"
#include "session.h"
#include "e_time.h"
#include "socket.h"

#define PUBLIC
#define PRIVATE static

#define INTERFACE "eth0"
//#define OUT_INTERFACE "eth1"

/* Following shortens all the type casts of pointer arguments */
#define SA  struct sockaddr
#define DPUTS printf(">>> called at %s:%3d <<<\n",__FILE__,__LINE__);

//#define HOST "165.242.42.217"
//#define HOST "172.29.34.137"

//#define LOCAL_NET "172.29.34.0"
//#define LOCAL_NET "165.242.42.0"
//#define DEST_NET "165.242.42.0"
//#define DEST_NET "172.29.34.0"
#define LOCAL_NET6 "3ffe:516:5102:0"
#define DEST_NET6 "3ffe:516:9120:0"

#define SEND_PORT "9004"
#define SERV_PORT "9004"

#define LOGFILE "ptgate.log"

#define SOCK_BUFLEN 65535

#define MAX_SEQ 65535

#define CCSDS 0

#define TRUE 1
#define FALSE 0
#define MAX_CLIENTS 5
#define MAX_DPORTS 5

#define TH 1
#define UNSPEC 1
#define TIME_VERBOSE 0
#define TIME_VERBOSE_E 0
#define MEASURE 0
#define RAW 1

#define ENABLE_BPF 0

#if TH
	#define BLOCK_SIZE 15
#else
	#define BLOCK_SIZE 255
#endif

#define MAXPKT BLOCK_SIZE * 3 /* max fec sequence number */
#define MAXPLSIZE 1540 /* max payload size */
#define MAXRSSIZE 1540 /* max reed-solomon buffer size */
#define MAXBUFSIZE 1580 /* max input/output buffer size */
#define MAX_RECVBUF_NUM 10000

pthread_cond_t data_recv_enc, data_recv_enc_th;
pthread_cond_t data_recv_dec, data_recv_dec_th;
pthread_mutex_t dummy_enc, dummy_dec, dummy_enc_th, dummy_dec_th;

/* global value for mesurement */
struct timeval DIV[10];
int t1,t2,t3,t4,t5;

typedef struct{
    char *interface;
    char *hostip;
} host_prof_t;

/* to display logs */
typedef struct{
    int enc_recv_pkt;
    int enc_send_pkt;
    int enc_fec_pkt;
    int enc_ring_pkt;
    int dec_recv_pkt;
    int dec_send_pkt;
    int dec_fec_pkt;
    int dec_ring_pkt;
    int loss_pkt;
    int recover_pkt;
    int allow;
    int deny;
    int dec_avg_time;
    int enc_avg_time;
    int relay_pkt;
    FILE *log_file;
} log_stat;

log_stat *l_st;

/* gateway headear */
typedef struct{
#if BYTE_ORDER == BIG_ENDIAN
    u_int32_t version:2;
    u_int32_t loss:1; /* padding */
    u_int32_t x:1; /* extension */
    u_int32_t reserved:4; 
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
    u_int32_t reserved:4; 
    u_int32_t x:1; /* extension */
    u_int32_t loss:1; /* loss */
    u_int32_t version:2;
#endif
    u_char pt; /* payload type */ 
    u_short seq; /* sequence number */
    ulong timestamp; 
} gw_hdr;

/* FEC header */
typedef struct{
    u_char next_hdr; /* option number */
    u_char next_size; /* option size */
    u_short reserved;
    u_char cs; /* code symbol size */
    u_char ds; /* the number of data symbol */
    u_short snbase; /* sequence number base */
    u_short blocksize; /* block size */
    u_short plsize; /* payload size */
} fec_hdr;

#if 0
/* thread struct */
typedef struct ThreadArgs{
  struct sockaddr_in CTL_Serv_Addr; /* encode RTCP server address */
  struct sockaddr_in CTL_Send_Addr; /* encode RTCP send address */
  struct sockaddr_in CTL_Addr; /* encode RTCP send address */  
  char *send_group_e;
  char *serv_group_e;
  char *send_group_d;
  char *serv_group_d;
} th_args_t;
#endif

/* Buffer struct */
typedef struct
{
    int size;
    int timestamp;
    u_char buf[MAXPLSIZE];
} buffer_t;

/* Ring buffer struct */
typedef struct
{
    int head;
    int tail;
    buffer_t bf[MAX_RECVBUF_NUM];
} ringbuf_t;

ringbuf_t *enc_recv_buf;
ringbuf_t *enc_th_buf;
ringbuf_t *dec_recv_buf;
ringbuf_t *dec_th_buf;

#endif /* _includes_h */
