/*
 * $Date: 2005/01/25 11:57:52 $
 * $Id: enc_redundant.c,v 1.15 2005/01/25 11:57:52 takashi Exp $
 * $Revision: 1.15 $
 */
#include "includes.h"
#include <net/ethernet.h>

#define BLKPKT 15

/* reed solomon buffer */
typedef u_char rsblock[BLOCK_SIZE];
rsblock rsbuf[MAXRSSIZE * 2];

/* sendto wrapper */
int wsendto(int fd, const void *ptr, size_t nbytes, int flags,
               const struct sockaddr *sa, socklen_t salen, double lossrate)
{
    if(loss_gen(lossrate)){
        if (sendto(fd, ptr, nbytes, flags, sa, salen) != nbytes){
                    printf("sendto error\n");
        }
    }
}

/* gwhdrに値を設定 */
int set_gwhdr(gw_hdr *gwhdr, u_int16_t seq, int payload_type, long int ts)
{
    gwhdr->version = 1;
    gwhdr->loss = 0;
    gwhdr->x = 1;
    gwhdr->reserved = 0;
    gwhdr->pt = payload_type;
    gwhdr->seq = htons(seq);
    gwhdr->timestamp = htonl(ts);
}
                                                                               
/* fechdrに値を設定 */
static int set_fechdr(fec_hdr *fechdr, int b_size, int nroots, u_int32_t snbase, int recvsize)
{
    fechdr->next_hdr = 99;
    fechdr->next_size = 0;
    fechdr->reserved = 0;
    fechdr->cs = b_size;
    fechdr->ds = b_size - nroots;
    fechdr->snbase = htons(snbase);
    fechdr->blocksize = htons(MAXPLSIZE);
    fechdr->plsize = htons(recvsize);
}

/* RSバッファにデータをコピー */
static int cp2rsbuf(int mm, u_int16_t fecseq, buffer_t *outbuf, int recvsize){
    int i;

    if(mm == 4){
        for(i = 0;i < recvsize;i++){
            rsbuf[i*2 + 8][fecseq] = 
                (*(outbuf[fecseq].buf + i + sizeof(gw_hdr) + sizeof(fec_hdr)) >> 4) & 0x0f;
            rsbuf[i*2 + 9][fecseq] = 
                *(outbuf[fecseq].buf + i + sizeof(gw_hdr) + sizeof(fec_hdr)) & 0x0f;
        }
    } else if(mm == 8){
        for(i = 0;i < recvsize;i++){
            rsbuf[i+4][fecseq] =
                *(outbuf[fecseq].buf + i + sizeof(gw_hdr) + sizeof(fec_hdr)) ;
        }
    }
}

/* RSバッファから出力バッファへ */
static int rsbuf2obuf(int mm, int nn, int b_size, buffer_t *outbuf, int head){
    int i;

    if(mm == 4){
       for(i = 0;i < MAXRSSIZE * 2;i += 2)
       {
           outbuf[head].buf[(i/2) + sizeof(gw_hdr)+8] = 
               ((rsbuf[i][head] << 4 & 0xf0) | (rsbuf[i + 1][head] & 0x0f));
       }
   } else if(mm == 8){
       for(i = 0;i < MAXRSSIZE ;i++)
       {
           outbuf[head].buf[i + sizeof(gw_hdr) + 8] = rsbuf[i][nn - b_size + head];
       }
   }
}

/* RSバッファの初期化 */
static init_rsbuf(int mm, int nn){
    int i;

    if(mm == 4){
        for(i = 0;i < MAXRSSIZE * 2;i++){
            memset(rsbuf[i], 0, nn);    
        }
    } else if (mm == 8){
        for(i = 0;i < MAXRSSIZE;i++){
            memset(rsbuf[i], 0, nn);    
        }
    }
}

/* RSエンコード関数の呼び出し */
static rs_encode(struct rs *rs, int mm , int nn, int nroots){
    int i;

    if(mm == 4){      
        for(i = 0;i < MAXRSSIZE * 2;i++){
#if CCSDS
            ENCODE_RS(rsbuf[i], &rsbuf[i][nn-nroots], 0);
#else
            ENCODE_RS(rs, rsbuf[i], &rsbuf[i][nn-nroots]);
#endif
        }
    } else if (mm == 8){
        for(i = 0;i < MAXRSSIZE;i++){
            ENCODE_RS(rs, rsbuf[i], &rsbuf[i][nn-nroots]);
        }
    }
}

/* エンコードメイン関数 */
int encode_func_char(session_t *sp)
{
    struct rs *rs = (struct rs *)sp->rs_handle;

    /* time value define */
    struct sockaddr_in SendAddr[3],ServAddr,ClntAddr;
    struct timeval pre_recvtime,after_recvtime;

    /* 出力用バッファ */
    buffer_t outbuf[BLKPKT];

    gw_hdr gwhdr;
    fec_hdr fechdr;  /* header define */ 
  
    int e_sendsock[MAX_CLIENTS]; /* sock value */
    int e_recvsock = 0; /* sock value */
    int recvsize = 0; /* recieve size */
    int mtp = 0;    /* Max Payload Size */
    int gwhdr_size = sizeof(gwhdr);
    int fechdr_size = sizeof(fechdr); /* header size */
    int i = 0;
    int j;
    int cnt, head, tail;
    int b_size = sp->b_size;
    u_int16_t seq = 0; /* sequence number */
    u_int16_t  snbase = 0; /* sequence number base */ 
    u_int16_t fecseq = 0; /* fec sequence number */ 
    u_int16_t  fecsnbase = 0; /* fec sequence number base */
    u_int16_t ClntAddrlen = 0;
    int timestamp = 0;

    long int ts = 0;
    struct timeval sect[6], end;
    struct ip_mreq multicastRequest;
    int sock_buflen = SOCK_BUFLEN;
    char flag = 0;

    SA *your_addr[MAX_CLIENTS];
    socklen_t your_adlen;
    struct addrinfo hints;

    /* 送信用ソケット作成 */
    for(cnt = 0; cnt < sp->session_num; cnt++){
        e_sendsock[cnt] = send_sock_create(sp->ESendAddr[cnt].addr, 
                                      sp->ESendAddr[cnt].port,
                                      (void **)&your_addr[cnt], &your_adlen);
        setsockopt(e_sendsock[cnt], SOL_SOCKET, SO_SNDBUF, 
                        &sock_buflen, sizeof(sock_buflen));
        if(sp->send_group_e)
        {
            if(setsockopt(e_sendsock[cnt], IPPROTO_IP, IP_MULTICAST_LOOP, 
                                    &flag, sizeof(flag)) < 0 ){
                    perror("SET NON LOOP failed");
            }
        }
    }

    /* init value */
    for(i = 0;i < BLKPKT;i++)
    {
        memset(outbuf[i].buf, 0, MAXBUFSIZE); 
    }

    /* init reed-solomon buffer init */
    for(i = 0;i < MAXRSSIZE * 2;i++){
        memset(rsbuf[i], 0, NN);
    }

    /* ミューテックスオブジェクトを生成する */
    pthread_mutex_init(&dummy_enc, NULL);

  /* main loop */
    while(1)
    {
        gettimeofday(&sect[0], NULL);

        /* data packet */
        /* データパケットを処理 */
        if(seq - snbase < b_size - NROOTS)
        {
            gettimeofday(&sect[1], NULL);

            /* FECシーケンス番号の計算 */
            fecseq = seq % b_size;

            ClntAddrlen=sizeof(ClntAddr);
            gettimeofday(&pre_recvtime,NULL);

            /* クリティカルセクションStart */
            pthread_mutex_lock(&dummy_enc);

            while(enc_recv_buf->tail == enc_recv_buf->head){
                /* 条件待ち */
                pthread_cond_wait(&data_recv_enc, &dummy_enc);
            }
            pthread_mutex_unlock(&dummy_enc);
            /* クリティカルセクションEnd */

            /* 受信したパケットをバッファにコピー */
            memcpy(outbuf[fecseq].buf+gwhdr_size+fechdr_size, enc_recv_buf->bf[enc_recv_buf->head].buf, enc_recv_buf->bf[enc_recv_buf->head].size);
            recvsize = enc_recv_buf->bf[enc_recv_buf->head].size;       
            timestamp = enc_recv_buf->bf[enc_recv_buf->head].timestamp;       

            /* リングバッファを進める */
            enc_recv_buf->head = ++enc_recv_buf->head % MAX_RECVBUF_NUM;

            gettimeofday(&after_recvtime,NULL);
            ts = after_recvtime.tv_sec * 1000000 - pre_recvtime.tv_sec * 1000000 + after_recvtime.tv_usec - pre_recvtime.tv_usec;
     
            /* FEC処理用バッファへデータのコピー */
            cp2rsbuf(MM, fecseq, outbuf, recvsize);

            /* maxplsize/plsize -> rsbuf */
            if(MM == 4)
            {
                rsbuf[0][fecseq] = (MAXPLSIZE>>12) & 0x0f;
                rsbuf[1][fecseq] = (MAXPLSIZE>>8) & 0x0f;
                rsbuf[2][fecseq] = (MAXPLSIZE>>4) & 0x0f;
                rsbuf[3][fecseq] = (MAXPLSIZE) & 0x0f;
                rsbuf[4][fecseq] = (recvsize>>12) & 0x0f;
                rsbuf[5][fecseq] = (recvsize>>8) & 0x0f;
                rsbuf[6][fecseq] = (recvsize>>4) & 0x0f;
                rsbuf[7][fecseq] = (recvsize) & 0x0f;
            } else if(MM == 8){
                rsbuf[0][fecseq] = (MAXPLSIZE>>8) & 0x00ff;
                rsbuf[1][fecseq] = MAXPLSIZE & 0x00ff;
                rsbuf[2][fecseq] = (recvsize>>8) & 0x00ff;
                rsbuf[3][fecseq] = recvsize & 0x00ff;
            }
 
            mtp= (recvsize > mtp) ? recvsize : mtp;

            /* gateway header set */
            set_gwhdr(&gwhdr, seq, 33, ts);
            //printf("enc %d %d ",gwhdr.seq, seq);

            /* fec header set */
            set_fechdr(&fechdr, b_size, NROOTS, snbase, recvsize);

            /* GWヘッダを送信用バッファへコピー */
            memcpy(outbuf[fecseq].buf,&gwhdr,gwhdr_size);
            /* FECヘッダを送信用バッファへコピー */
            memcpy(outbuf[fecseq].buf+gwhdr_size,&fechdr,fechdr_size);

            /* data packet send */
            /* データパケット送出 */
            for(cnt = 0; cnt < sp->session_num; cnt++){
                if(wsendto(e_sendsock[cnt], outbuf[fecseq].buf, recvsize + gwhdr_size + fechdr_size, 0, your_addr[cnt], your_adlen, sp->lossrate) == -1) 
                {
                    perror("send() failed unspec");
                    exit(0);
                }
                l_st->enc_send_pkt++; 
            }

            /* sequence increament */
            /* シーケンス番号の加算 */
            seq++;

//          printf("enc_red %d [us]\n", my_clock() - timestamp);
    
            /*gettimeofday(&after_data,NULL);
            sum_buf_delay+=after_data.tv_sec*1000000+after_data.tv_usec-pre_data.tv_sec*1000000-pre_data.tv_usec;*/
            /* データパケットの処理終了 */
            /* ここでスレッドに投げればよい */     
            gettimeofday(&sect[2], NULL);
        }
        else if(seq - snbase >= b_size - NROOTS)
        {
            /* 冗長パケット処理フェーズ */
            /* rs packet process */
            gettimeofday(&sect[3], NULL);

            /* rs encode  process */
            /* RSエンコード演算 */
            rs_encode(rs, MM, NN, NROOTS);
#if 0
            if(MM == 4){      
                for(i = 0;i < MAXRSSIZE * 2;i++){
#if CCSDS
                    ENCODE_RS(rsbuf[i], &rsbuf[i][NN-NROOTS], 0);
#else
                    ENCODE_RS(rs, rsbuf[i], &rsbuf[i][NN-NROOTS]);
#endif
                }
            } else if (MM == 8){
                for(i = 0;i < MAXRSSIZE;i++){
                    ENCODE_RS(rs, rsbuf[i], &rsbuf[i][NN-NROOTS]);
                }
            }
#endif

#if 0
        /* For DEBUG */
    u_char tblock[NN];
    int errors;
    int errlocs[NN];
    int derrlocs[NROOTS];
    int derrors;
    int errval, errloc;
    int erasures;
    int decoder_errors = 0;
      /* Make temp copy, seed with errors */
      memcpy(tblock,rsbuf,sizeof(tblock));
      memset(errlocs,0,sizeof(errlocs));
      memset(derrlocs,0,sizeof(derrlocs));
      erasures=0;
    errors = 4;
      for(i=0;i<errors;i++){
    do {
              errval = random() & NN;
    } while(errval == 0); /* Error value must be nonzero */

    do {
//      errloc = random() % NN;
    } while(errlocs[errloc] != 0); /* Must not choose the same location twice */

    errlocs[errloc] = 1;

#if 0
    if(random() & 1) /* 50-50 chance */
      derrlocs[erasures++] = errloc;
#endif
    tblock[errloc] ^= errval;
      }

      derrors = DECODE_RS(rs,tblock,derrlocs,erasures);

      if(derrors != errors){
    printf(" decoder says %d errors, true number is %d\n",derrors,errors);
    decoder_errors++;
      } else {
    puts("ok");
//    printf(" decoder says %d errors, true number is %d\n",derrors,errors);
    }
#endif


#if 0
        int nco;
    int eras_pos[BLOCK_SIZE];
    eras_pos[0] = 0;
    eras_pos[1] = 1;
    eras_pos[2] = 2;
    memset(rsbuf[0], 0, NN);
//    eras_pos[3] = 3;
//    eras_pos[4] = 4;
        nco = DECODE_RS(rs, rsbuf[i], eras_pos, 0);

        if(nco < 0){
            printf("!!DECODE ERROR!!\n");
        } else {
            printf("!!DECODE OK!! %d\n", nco);
    }
#endif
      
      /* rs packet set/send */
     
            gettimeofday(&sect[4], NULL);
            /* 冗長パケット送信 */
            for(head = b_size - NROOTS; head < b_size; head++)
            {
                /* FECシーケンス番号の計算 */
                fecseq = seq % b_size;
        
                /* rsbuf -> outbuf */
                /* RSバッファから送信用バッファへ */
                rsbuf2obuf(MM, NN, b_size, outbuf, head);
          
                /* gateway header set */
                set_gwhdr(&gwhdr, seq, 44, 0);

                /*fec header set */
                set_fechdr(&fechdr, b_size, NROOTS, snbase, recvsize);
    
                /* header copy */
                /* GWヘッダを送信用バッファへコピー */
                memcpy(outbuf[head].buf,&gwhdr,gwhdr_size);      
                /* FECヘッダを送信用バッファへコピー */
                memcpy(outbuf[head].buf+gwhdr_size,&fechdr,fechdr_size-4);    

                /* 冗長パケットを送信 */
                for(cnt = 0; cnt < sp->session_num; cnt++){
                    if(wsendto(e_sendsock[cnt], outbuf[fecseq].buf, mtp + gwhdr_size + fechdr_size, 0, your_addr[cnt], your_adlen, sp->lossrate) == -1) 
                    {
                        perror("send() failed unspec");
                        exit(0);
                    }
//                  printf("%d %d %d %d\n",recvsize+gwhdr_size+fechdr_size,recvsize, gwhdr_size, fechdr_size);
                    l_st->enc_fec_pkt++;
                }

                /* 後処理 */
          
                /* シーケンス番号が一周した場合の処理 */ 
                if(seq == (int)(65535/(b_size * 3))*(b_size * 3) - 1)
                {
                    seq=0;
                }
                else 
                {
                    seq++;
                }
            }
            /* 冗長パケット送信フェーズ終わり*/

            /* snbase set */
            if(seq % b_size == 0){
                snbase = seq;
            }

            /* 最大ペイロード長を初期化 */
            mtp = 0;

            /* reed-solomon buffer init */
            init_rsbuf(MM, NN);

            gettimeofday(&sect[5], NULL);
        }
        /* 冗長パケット処理フェーズ終わり */

        gettimeofday(&end, NULL);

#if TIME_VERBOSE_E
        int count;
        FILE *fp;
        double all, enc;
        double s_all, s_enc;
        char fname[255];
        count++;
        all = e_time("\nALL:",&sect[0], &end);
        e_time(" +- data_pkt",&sect[1], &sect[2]);
        enc = e_time(" +- encode",&sect[3], &sect[4]);
        e_time(" +- rs_pkt",&sect[4], &sect[5]);
        e_time(" +- rs_all",&sect[3], &sect[5]);
#if MEASURE
        sprintf(fname,"enc-%d.txt",b_size);
        if(count == 1){
                fp = fopen(fname, "w");
        } else if(count < 10000){
                s_all += all;
                s_enc += enc;
                fprintf(fp,"%.3f %.3f \n",s_all/count,s_enc/count);
        } else {
                fclose(fp);
        }
#endif
#endif
    /* メインループ終わり */
    }
}
