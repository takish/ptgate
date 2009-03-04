/*
 * $Date: 2005/01/25 11:57:52 $
 * $Id: enc_through.c,v 1.17 2005/01/25 11:57:52 takashi Exp $
 * $Revision: 1.17 $
 */
#include "includes.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>

/* FECバッファ構造体 */
/*typedef struct {
  int head;
  int tail;
  buffer_t bf[MAXPKT];
} fecbuf_t;
*/

void *ENC_TH_Loop_Thread(session_t *sp)
{
    struct sockaddr_in SendAddr[3],ServAddr;

    /* IPパケット用バッファ */
//    buffer_t ipbuf;

    char buffer[MAXBUFSIZE];
    u_int16_t seq = 0;
    u_int32_t ts = 0;

    gw_hdr gwhdr;
  
    int e_sendsock[MAX_CLIENTS]; /* socket for sending packet */
    int recvsize = 0; /* recieve size */
    int i, cnt;
    struct ip_mreq multicastRequest;
    int sock_buflen = SOCK_BUFLEN;
    char flag = 0;
    int timestamp = 0;

    SA *your_addr[MAX_CLIENTS];
    socklen_t your_adlen;
    struct addrinfo hints;
    struct ifreq ifr;
    struct sockaddr_ll sll;
    static int enc_cnt = 1, enc_avg_sum = 0;

    for(cnt = 0; cnt < sp->session_num; cnt++){
        e_sendsock[cnt] = send_sock_create(sp->ESendAddr[cnt].addr, 
                                      sp->ESendAddr[cnt].port,
                                      (void **)&your_addr[cnt], &your_adlen);
//        setsockopt(e_sendsock[cnt], SOL_SOCKET, SO_SNDBUF, &sock_buflen, sizeof(sock_buflen));
        if(sp->send_group_e)
        {
            if(setsockopt(e_sendsock[cnt], IPPROTO_IP, IP_MULTICAST_LOOP, 
                                    &flag, sizeof(flag)) < 0 ){
                    perror("SET NON LOOP failed");
            }
        }
    }


    /* init value */
//    for(i = 0;i < MAXPKT;i++)
//    {
//        memset(inbuf.bf[i].buf, 0, MAXBUFSIZE);
//      memset(outbuf.bf[i].buf, 0, MAXBUFSIZE); 
//    }

//      memset(ipbuf.buf, 0, MAXBUFSIZE);

#if TH
    pthread_mutex_init(&dummy_enc_th, NULL);
#endif

    /* main loop */
    /* 受信してエンコードバッファに入れる */
    while(1)
    {
        pthread_mutex_lock(&dummy_enc_th);

        while(enc_th_buf->tail == enc_th_buf->head){
            pthread_cond_wait(&data_recv_enc_th, &dummy_enc_th);
        }
        pthread_mutex_unlock(&dummy_enc_th);

//        memcpy(inbuf.bf[0].buf, enc_th_buf->bf[enc_th_buf->head].buf, enc_th_buf->bf[enc_th_buf->head].size);
        /* 受信パケットを送信用バッファへコピー */
        memcpy(buffer+sizeof(gw_hdr), enc_th_buf->bf[enc_th_buf->head].buf, recvsize);
//        memcpy(ipbuf.buf, enc_th_buf->bf[enc_th_buf->head].buf, enc_th_buf->bf[enc_th_buf->head].size);
        recvsize = enc_th_buf->bf[enc_th_buf->head].size;       
        timestamp = enc_th_buf->bf[enc_th_buf->head].timestamp;       

        enc_th_buf->head = ++enc_th_buf->head % MAX_RECVBUF_NUM;

        /* TCP */
        /* ゲートウェイヘッダ付加 */
        set_gwhdr(&gwhdr, seq, 34, ts);

        /* GWhdrを送信用バッファにコピー */
        memcpy(buffer, &gwhdr, sizeof(gw_hdr));
        /* 転送用IPパケットを送信用バッファにコピー */
//        memcpy(buffer+sizeof(gw_hdr), inbuf.bf[0].buf, recvsize);
//        memcpy(buffer+sizeof(gw_hdr), ipbuf.buf, recvsize);

//        printf("send: %d %d %d %d %d size: %d\n", gwhdr.version, gwhdr.x, gwhdr.loss, gwhdr.pt, gwhdr.seq, sizeof(gw_hdr));
//printf("\tsend:%d\n",recvsize);
        /* マルチポイントに送信 */
        for(cnt = 0; cnt < sp->session_num; cnt++){
//            if(sendto(e_sendsock[cnt], inbuf.bf[0].buf,
//         if(loss_gen(lossrate)){
            if(wsendto(e_sendsock[cnt], buffer,
                recvsize + sizeof(gw_hdr), 0, your_addr[cnt], your_adlen, sp->lossrate) == -1) 
            {
                perror("send() failed unspec");
                exit(0);
            }
//        e_point(&DIV[1]);
        gettimeofday(&DIV[1], NULL);

        t4 = my_clock();
        enc_avg_sum += t4 - timestamp;       
//        printf("enc %d %d [us] avg %d [us]\n", enc_cnt, t4-t3, enc_avg_sum/enc_cnt);
        l_st->enc_avg_time = enc_avg_sum/enc_cnt;
        //     e_time("dec",&DIV[2], &DIV[3]);
        enc_cnt++;
        
//        e_time("enc",&DIV[0], &DIV[1]);
//        printf("%d\n",recvsize);
//         }
//            printf("%d %d %d %d\n",recvsize+gwhdr_size+fechdr_size,recvsize, gwhdr_size, fechdr_size);
            l_st->enc_send_pkt++;
        }

        if(seq == MAX_SEQ){
            seq = 0;
        } else {
            seq++;
        }
    }
}
