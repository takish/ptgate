/*
 * $Date: 2005/01/21 04:22:09 $
 * $Id: dec_through.c,v 1.12 2005/01/21 04:22:09 takashi Exp $
 * $Revision: 1.12 $
 */
#include "includes.h"
#include <time.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

/* buffer struct */
typedef struct{
    int size;
    u_char status;
    u_char buf[MAXBUFSIZE];
    long int ts;
} d_buffer_t;

/* input buffer struct */
typedef struct {
    int head;
    int tail;
    d_buffer_t bf[MAXPKT];
//} inbuf_t, outbuf_t;
} outbuf_t;

/* output buffer struct */
/*typedef struct {
    int head;
    int tail;
    d_buffer_t bf[MAXPKT]; 
} outbuf_t;
*/

//int decode_through(session_t *sp) 
void *DEC_TH_Loop_Thread(session_t *sp)
{
    struct sockaddr_in SendAddr[3],ServAddr;

    /* extension header */
    gw_hdr gwhdr;
    fec_hdr fechdr;

    /* input/output buffer define */
    buffer_t ipbuf;
//    inbuf_t inbuf;
    outbuf_t outbuf;
    outbuf_t *poutbuf;
    int d_sendsock;
    int d_sendsock6;
    int d_recvsock;
    int i;
//    int cnt=0;
    u_char recvbuf[MAXBUFSIZE];
    struct timeval sect[6],end;
    struct ip_mreq multicastRequest;
    int sock_buflen = SOCK_BUFLEN;
    char flag = 0;
    int timestamp = 0;

    struct sockaddr *your_addr;
    socklen_t your_adlen;
    struct addrinfo hints;

    /* for debug */
#if 0
    int total_size;
    int count;
    FILE *fp;
    double all,buf,dec;
    double s_all,s_buf,s_dec;
    char fname[255];
#endif
    static u_short last_seq = 0, curr_seq= 0;

    poutbuf = &outbuf;
#if RAW
    d_sendsock = send_raw_sock_create();

    if(sp->enable_ipv6){
        d_sendsock6 = send_raw_sock6_create();
    }
#else
    d_sendsock = send_sock_create(sp->DSendAddr.addr, sp->DSendAddr.port, (void **)&your_addr, &your_adlen);
    setsockopt(d_sendsock, SOL_SOCKET, SO_SNDBUF, &sock_buflen, sizeof(sock_buflen));
    if(sp->send_group_d) {
        if(setsockopt(d_sendsock, IPPROTO_IP, IP_MULTICAST_LOOP, &flag, sizeof(flag)) < 0)
        {
            perror("SET NON LOOP failed");
        }
    }
#endif

    /* init value */
    for(i = 0;i < MAXPKT;i++)
    {
//        memset(inbuf.bf[i].buf, 0, MAXBUFSIZE);
        memset(outbuf.bf[i].buf, 0, MAXBUFSIZE); 
//        inbuf.bf[i].status = 0;
//        outbuf.bf[i].status = 0;
//        inbuf.bf[i].size = 0;
        outbuf.bf[i].size = 0;
    }

    /* main loop */
    while(1)
    {
        pthread_mutex_lock(&dummy_dec_th);

        while(dec_th_buf->tail == dec_th_buf->head){
            pthread_cond_wait(&data_recv_dec_th, &dummy_dec_th);
        //    printf("now waiting\n");
        }

        pthread_mutex_unlock(&dummy_dec_th);

        /* 受信バッファから入力バッファへ */
        /* recvbuf -> inbuf */
//        memcpy(inbuf.bf[0].buf, dec_th_buf->bf[dec_th_buf->head].buf, dec_th_buf->bf[dec_th_buf->head].size);
        memcpy(ipbuf.buf, dec_th_buf->bf[dec_th_buf->head].buf, dec_th_buf->bf[dec_th_buf->head].size);
//        memcpy(inbuf.bf[0].buf, dec_th_buf->bf[dec_th_buf->head].buf+sizeof(gw_hdr), dec_th_buf->bf[dec_th_buf->head].size-sizeof(gw_hdr));
//        inbuf.bf[0].size = dec_th_buf->bf[dec_th_buf->head].size;
        ipbuf.size = dec_th_buf->bf[dec_th_buf->head].size-sizeof(gw_hdr);
//        inbuf.bf[0].size = dec_th_buf->bf[dec_th_buf->head].size-sizeof(gw_hdr);
//        inbuf.bf[0].status = 1;

        l_st->dec_recv_pkt++;
//
//        memcpy(&gwhdr, inbuf.bf[0].buf, sizeof(gw_hdr));
        memcpy(&gwhdr, ipbuf.buf, sizeof(gw_hdr));
        curr_seq = ntohs(gwhdr.seq);

//        printf("recv: %d %d %d %d %d\n",gwhdr.version, gwhdr.x, gwhdr.loss, gwhdr.pt, gwhdr.seq);
//        printf("%d %d\n",gwhdr.seq, last_seq);
        if(last_seq < curr_seq){
            l_st->loss_pkt += curr_seq - last_seq - 1; 
        } else {
            l_st->loss_pkt += curr_seq + MAX_SEQ - last_seq; 
        }

        /* 入力バッファからGWヘッダを除いて出力バッファへ */
//        memcpy(outbuf.bf[0].buf, inbuf.bf[0].buf + sizeof(gw_hdr), inbuf.bf[0].size);
        memcpy(outbuf.bf[0].buf, ipbuf.buf + sizeof(gw_hdr), ipbuf.size);
        outbuf.bf[0].size = ipbuf.size;
        last_seq = ntohs(gwhdr.seq);

        /* 受信バッファを一つ減らす */
        dec_th_buf->head = ++dec_th_buf->head % MAX_RECVBUF_NUM;

//        printf("%d\n", my_clock() - timestamp);
        send_packets(d_sendsock, d_sendsock6, poutbuf, 0);
    }
}
