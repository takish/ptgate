/*
 * $Date: 2005/01/21 13:21:39 $
 * $Id: decode_func.c,v 1.26 2005/01/21 13:21:39 takashi Exp $
 * $Revision: 1.26 $
 */
#include "includes.h"
#include "rtc.h"
#include <time.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>

#define RTC_HZ 8192
#define FLAG_ERASURE 0 /* Randomly flag 50% of errors as erasures */

/* rs buffer struct */ 
typedef u_char rsblock[BLOCK_SIZE];

/* Reed-Solomonバッファ */
struct{
    int no_eras;                /* エラー数 */  
    int eras_pos[BLOCK_SIZE];   /* エラー箇所 */
    rsblock bf[MAXRSSIZE*2];    /* RSバッファ */
} rsbuf;

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
} inbuf_t;

/* output buffer struct */
typedef struct {
    int head;
    int tail;
    d_buffer_t bf[MAXPKT]; 
} outbuf_t;

/* 最終パケット書き出し */
int send_packets(int d_sendsock, int d_sendsock6, outbuf_t *outbuf, int idx){
    int ip_ver;
	struct sockaddr_in dst_sin;
	struct sockaddr_in6 dst_sin6;
	struct iphdr *iph;
	struct ip6_hdr *ipv6h;
    static int dec_cnt = 1;
    static int avg_sum = 0;

    ip_ver = v4orv6(outbuf->bf[idx].buf);

    if(ip_ver == 4){
        memset(&dst_sin, 0, sizeof(dst_sin));
        iph = (struct iphdr *)(outbuf->bf[idx].buf);
        dst_sin.sin_addr.s_addr = iph->daddr;
        dst_sin.sin_family = AF_INET;

//        printf("%d %d\n",outbuf->bf[idx].size, ntohs(iph->tot_len));
        /*  IPヘッダのサイズを書き込みサイズとする */
        if(sendto(d_sendsock, outbuf->bf[idx].buf, 
//            outbuf->bf[idx].size, 0, (SA *)&dst_sin, 
            ntohs(iph->tot_len), 0, (SA *)&dst_sin, 
            sizeof(dst_sin)) == -1) {
                printf("%s\n",inet_ntoa(dst_sin.sin_addr));
                perror("send() failed at send_packets v4");
                exit(0);
        } else {
            l_st->dec_send_pkt++;
        }
    }
    else if (ip_ver == 6 && (d_sendsock6 != 0))
    {
        memset(&dst_sin6, 0, sizeof(dst_sin6));
        ipv6h = (struct ip6_hdr *)(outbuf->bf[idx].buf);
        memcpy(&dst_sin6.sin6_addr,&(ipv6h->ip6_dst),sizeof(ipv6h->ip6_dst));
        dst_sin6.sin6_family = AF_INET6;
 
        if(sendto(d_sendsock6, outbuf->bf[idx].buf, outbuf->bf[idx].size, 0, (SA *)&dst_sin6, sizeof(dst_sin6)) == -1) {
            perror("send IPv6 raw socket failed");
            exit(0);
        } else {
            l_st->dec_send_pkt++;
        }
    } else {
        printf("unknown ip version: %d %d\n", ip_ver, outbuf->bf[idx].size);
    }
  

    e_point(&DIV[3]);
//    gettimeofday(&DIV[3],NULL);
    t2 = my_clock();
    avg_sum += t2 - t1;
//    printf("dec %d %d [us] avg %d [us]\n", dec_cnt, t2-t1, avg_sum/dec_cnt);
    l_st->dec_avg_time = avg_sum/dec_cnt;
//    e_time("dec",&DIV[2], &DIV[3]);
    dec_cnt++;
}

/* This function is not still using */
int send_packets2(int d_sendsock, int d_sendsock6, char *recvbuf, int recvsize){
    int ip_ver;
	struct sockaddr_in dst_sin;
	struct sockaddr_in6 dst_sin6;
	struct iphdr *iph;
	struct ip6_hdr *ipv6h;

    ip_ver = v4orv6(recvbuf);

    ip_dump(recvbuf);
    if(ip_ver == 4){
        memset(&dst_sin, 0, sizeof(dst_sin));
        iph = (struct iphdr *)(recvbuf);
        dst_sin.sin_addr.s_addr = iph->daddr;
        dst_sin.sin_family = AF_INET;

        if(sendto(d_sendsock, recvbuf, recvsize, 0, (SA *)&dst_sin, sizeof(dst_sin)) == -1) {
                printf("%s\n",inet_ntoa(dst_sin.sin_addr));
                perror("send() failed at send_packets v4");
                exit(0);
        } else {
            l_st->dec_send_pkt++;
        }
    }
        else if (ip_ver == 6){
        memset(&dst_sin6, 0, sizeof(dst_sin6));
        ipv6h = (struct ip6_hdr *)(recvbuf);
        memcpy(&dst_sin6.sin6_addr,&(ipv6h->ip6_dst),sizeof(ipv6h->ip6_dst));
        dst_sin6.sin6_family = AF_INET6;

        if(sendto(d_sendsock6, recvbuf, recvsize, 0, (SA *)&dst_sin6, sizeof(dst_sin6)) == -1) {
            perror("send() failed at unspec1b");
            exit(0);
        } else {
            l_st->dec_send_pkt++;
        }
    } else {
        printf("unknown ip version: %d\n", ip_ver);
    }
}

int decode_func_char(session_t *sp) 
{
    struct rs *rs = (struct rs *)sp->rs_handle;
    struct sockaddr_in SendAddr[3],ServAddr,ClntAddr;

    /* extension header */
    gw_hdr gwhdr;
    fec_hdr fechdr;

    /* input/output buffer define */
    inbuf_t inbuf;
    outbuf_t outbuf;
    outbuf_t *poutbuf;
    int d_sendsock;
    int d_sendsock6 = 0;
    int d_recvsock;
    int recvsize=0;
    int fechdr_size=sizeof(fechdr);
    int gwhdr_size=sizeof(gwhdr);
    int i=0;
    int j=0;
    int k=0;
//    int cnt=0;
    int last_snbase=0;
    int ncorrect=0;
    int send=0;
    int rtc=0;
    long int sum_ts=0;
    int loss_flag=0;
    int loss_num=0;
    int reco_num=0;
    int fec_loss=0;
    int cs, ds;
    int b_size;
    static int last_cs, last_ds;
 
    u_short seq=0;
    u_short snbase=0;
    u_short fecseq=0;
    u_short fecsnbase=0;
    u_short curr_snbase=0;
    u_int32_t ClntAddrlen=0;
    u_char recvbuf[MAXBUFSIZE];

    int genpoly = 0; 
    int mm = 0; 
    int nroots=0;

    struct timeval sect[6],end;
    struct ip_mreq multicastRequest;
    int sock_buflen = SOCK_BUFLEN;
    char flag = 0;

	struct sockaddr *your_addr;
	socklen_t your_adlen;
	struct addrinfo hints;

	struct sockaddr_in dst_sin;
/*	struct iphdr *iph;
	struct ip6_hdr *ipv6h;
	struct sockaddr_in6 dst_sin6;
	int ip_ver;
    */
//for debug
	int total_size;
	int count;
	FILE *fp;
	double all,buf,dec;
	double s_all,s_buf,s_dec;
	char fname[255];

    poutbuf = &outbuf;
#if RAW
	d_sendsock = send_raw_sock_create();

    if(sp->enable_ipv6){
	    d_sendsock6 = send_raw_sock6_create();
    }
#else
    d_sendsock = send_sock_create(sp->DSendAddr.addr, 
								 sp->DSendAddr.port, 
								 (void **)&your_addr, &your_adlen);
    setsockopt(d_sendsock, SOL_SOCKET, SO_SNDBUF, 
					&sock_buflen, sizeof(sock_buflen));
    if(sp->send_group_d) {
        if(setsockopt(d_sendsock, IPPROTO_IP, IP_MULTICAST_LOOP, 
								  &flag, sizeof(flag)) < 0)
        {
            perror("SET NON LOOP failed");
        }
    }
#endif

#if !TH
	d_recvsock = recv_sock_create(NULL, sp->DServAddr.port, &your_adlen);

    if(sp->serv_group_d) {
        multicastRequest.imr_multiaddr.s_addr = inet_addr(sp->serv_group_d);
        multicastRequest.imr_interface.s_addr = htonl(INADDR_ANY);
        if(setsockopt(d_recvsock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&multicastRequest, sizeof(multicastRequest)) < 0)
		  {
            perror("JOIN failed");
        }
    }
 
    setsockopt(d_recvsock, SOL_SOCKET, SO_RCVBUF, &sock_buflen, sizeof(sock_buflen));
#endif

    /* init value */
    for(i = 0;i < MAXPKT;i++)
    {
        memset(inbuf.bf[i].buf, 0, MAXBUFSIZE);
        memset(outbuf.bf[i].buf, 0, MAXBUFSIZE); 
        inbuf.bf[i].status = 0;
        outbuf.bf[i].status = 0;
        inbuf.bf[i].size = 0;
        outbuf.bf[i].size = 0;
    }

    for(i = 0;i < MAXRSSIZE * 2;i++){
        memset(rsbuf.bf[i], 0, NN);
    }

    memset(rsbuf.eras_pos, 0, NN);
    rsbuf.no_eras = 0;  
    ClntAddrlen = sizeof(ClntAddr);

    /* main loop */
    while(1)
    { 
        i = 0;
        gettimeofday(&sect[0], NULL);
    while(1)
    {
        last_snbase = curr_snbase;
        /* recv */
        ClntAddrlen = sizeof(ClntAddr);
	  
#if TH
        pthread_mutex_lock(&dummy_dec);

        while(dec_recv_buf->tail == dec_recv_buf->head){
            pthread_cond_wait(&data_recv_dec, &dummy_dec);
        //	printf("now waiting\n");
        }

		pthread_mutex_unlock(&dummy_dec);
		/* header set */
        /* 各々のヘッダを抽出 */
		memcpy(&gwhdr, dec_recv_buf->bf[dec_recv_buf->head].buf, gwhdr_size);
		memcpy(&fechdr, dec_recv_buf->bf[dec_recv_buf->head].buf + gwhdr_size, fechdr_size);
        /* block size 及び data simbol sizeを取り出す */
		b_size = fechdr.cs;
		ds = fechdr.ds;
#else
		if((recvsize = 
		recvfrom(d_recvsock, recvbuf, MAXBUFSIZE, 0, (SA *)&ClntAddr, &ClntAddrlen)) < 0)
	    {
	      perror("recv() failed");
	      exit(0);
	    }
	  
	  /* header set */
	  memcpy(&gwhdr, recvbuf, gwhdr_size);
	  memcpy(&fechdr, recvbuf + gwhdr_size, fechdr_size);

	  b_size = (fechdr.cs);
	  ds = (fechdr.ds);
#endif
	  curr_snbase = ntohs(fechdr.snbase);

	  if(seq - b_size + 1 > (int)(65535 / (b_size * 3)) * (b_size * 3) - b_size){
		  printf("%d %d\n",last_snbase, curr_snbase);
	  }

		if(last_snbase != (int)(65535 / (b_size * 3)) * (b_size * 3) - b_size)
	    {
	      if(curr_snbase > last_snbase)
	      break;
	    } else if (last_snbase == (int)(65535 / (b_size * 3)) * (b_size * 3) - b_size) {
		/* 一周したとき */
	      if(curr_snbase < last_snbase)
		break;
	    }
	  
   	  seq = ntohs(gwhdr.seq);
	  snbase = ntohs(fechdr.snbase);

//      printf("%d %d %d %d %d\n", seq, snbase, b_size, cs, ds);

	  if(b_size == 15){
	    cs = 15;
	  }else{
	    cs = 255;
	  }

if((cs != last_cs) || (ds != last_ds)){
// cs = 2^x - 1
//	cs = (2 << x) - 1;
	  //
	switch(cs){
		case 15:
		 mm = 4;
		 genpoly = 0x13;
		 break;
		case 31:
		 mm = 5;
		 genpoly = 0x25;
		 break;
		case 63:
		 mm = 6;
		 genpoly = 0x43;
		 break;
		case 127:
		 mm = 7;
		 genpoly = 0x89;
		 break;
	        case 255:	
		 mm = 8;
		 genpoly = 0x11d;
		 break;
	}
		nroots = b_size - ds;
#if 1
//printf("%d %d\n",mm, nroots);
	 if((rs = 
		init_rs_char(mm, genpoly, 1, 1, nroots, 0)) == NULL)
	{
		printf("init_rs_char failed!\n");
	} else {
		fprintf(stdout, "#### Change RS (%d,%d) code\n", cs, ds);
	}
#endif
}

    last_cs = cs;
    last_ds = ds;

	  fecseq = seq % b_size;
	  fecsnbase = snbase % (b_size * 3);
	  outbuf.bf[fecseq+fecsnbase].ts = ntohl(gwhdr.timestamp);

//if(seq % 10000 == 0)
//	printf("%d\n",seq);
    if(seq > (int)(65535 / (b_size * 3)) * (b_size * 3) - 1)
        printf("###ROTATE### %d\n", seq);

	  /* recvbuf -> inbuf */
#if TH
	  memcpy(inbuf.bf[fecseq+fecsnbase].buf, dec_recv_buf->bf[dec_recv_buf->head].buf, dec_recv_buf->bf[dec_recv_buf->head].size);
	  inbuf.bf[fecseq+fecsnbase].size = dec_recv_buf->bf[dec_recv_buf->head].size;
      if(inbuf.bf[fecseq+fecsnbase].size < 1000){
//      printf("%d %d %d\n", fecseq, fecsnbase, inbuf.bf[fecseq+fecsnbase].size);
      }
#else
	  memcpy(inbuf.bf[fecseq+fecsnbase].buf, recvbuf, recvsize);
	  inbuf.bf[fecseq+fecsnbase].size = recvsize;
#endif
	  inbuf.bf[fecseq+fecsnbase].status = 1;

#if TH
	  dec_recv_buf->head = ++dec_recv_buf->head % MAX_RECVBUF_NUM;
#endif
	  	  
	  if(gwhdr.pt == 44){
		l_st->dec_fec_pkt++;
	  }

	  /* send */
	  if(gwhdr.pt == 33)
	    {
		l_st->dec_recv_pkt++;

	      if (outbuf.bf[i + send].status == 1)
		{
//				printf("%s\n",outbuf.bf[i+send].size);
#if RAW

//			if(write(d_sendsock[cnt], (void *)outbuf.bf[i+send].buf, outbuf.bf[i+send].size) == -1)
            send_packets(d_sendsock, d_sendsock6, poutbuf, i+send);

/*			ip_ver = v4orv6(outbuf.bf[i+send].buf);
			if(ip_ver == 4){
				memset(&dst_sin, 0, sizeof(dst_sin));
				iph = (struct iphdr *)(outbuf.bf[i+send].buf);
				dst_sin.sin_addr.s_addr = iph->daddr;
				dst_sin.sin_family = AF_INET;

				if(sendto(d_sendsock[cnt], outbuf.bf[i+send].buf, 
					outbuf.bf[i+send].size, 0, (SA *)&dst_sin, 
					sizeof(dst_sin)) == -1)
				{
					printf("%s\n",inet_ntoa(dst_sin.sin_addr));
					perror("send() failed at unspec1");
					exit(0);
                } else {
                    l_st->dec_send_pkt++;
                }
			} else if (ip_ver == 6){
				memset(&dst_sin6, 0, sizeof(dst_sin6));
				ipv6h = (struct ip6_hdr *)(outbuf.bf[i+send].buf);
				memcpy(&dst_sin6.sin6_addr,&(ipv6h->ip6_dst),sizeof(ipv6h->ip6_dst));
				dst_sin6.sin6_family = AF_INET6;

				if(sendto(d_sendsock6[cnt], outbuf.bf[i+send].buf, 
				outbuf.bf[i+send].size, 0, (SA *)&dst_sin6, 
				sizeof(dst_sin6)) == -1)
				{
					perror("send() failed at unspec1");
					exit(0);
                } else {
                    l_st->dec_send_pkt++;
                }

			}
*/
#else
			if(sendto(d_sendsock, outbuf.bf[i+send].buf, 
				outbuf.bf[i+send].size, 0, your_addr, your_adlen) == -1)
			{
				perror("send() failed at unspec1");
				exit(0);
			}
#endif
		}

		i++;  
	    }  
	}
		gettimeofday(&sect[1], NULL);

       rtc = open_rtc(RTC_HZ);

       for(j = 0;j < b_size - NROOTS;j++){
	 		sum_ts += outbuf.bf[j+send].ts;
       }
      
       k = sum_ts / (122 * b_size);

       for(j = 0;j < b_size - NROOTS;j++){
	 		outbuf.bf[j+send].ts = 0;
       }
   
      /* send(loss) */
        if(i < b_size - NROOTS)
        {
            while(i < b_size - NROOTS)
            {
                for(j = 0;j < k;j++)
                {
                    wait_rtc(rtc);
                }
	     
	      if(outbuf.bf[i+send].status == 1)
		{      
#if RAW
            send_packets(d_sendsock, d_sendsock6, poutbuf, i+send);
/*			memset(&dst_sin, 0, sizeof(dst_sin));
			iph = (struct iphdr *)(outbuf.bf[i+send].buf);
//			printf("%x\n",iph->daddr);
			dst_sin.sin_addr.s_addr = iph->daddr;
			dst_sin.sin_family = AF_INET;

//			if(write(d_sendsock[cnt], (void *)outbuf.bf[i+send].buf, outbuf.bf[i+send].size) == -1)
			if(sendto(d_sendsock[cnt], outbuf.bf[i+send].buf, 
				outbuf.bf[i+send].size, 0, (SA *)&dst_sin, 
				sizeof(dst_sin)) == -1)
				{
					printf("%s\n",inet_ntoa(dst_sin.sin_addr));
					perror("send() failed at unspec2");
					exit(0);
				} else {
				    l_st->dec_send_pkt++;		 
                }
*/
#else
				if(sendto(d_sendsock, outbuf.bf[i+send].buf, 
					outbuf.bf[i+send].size, 0, your_addr, your_adlen) == -1)
				{
					printf("%s\n",inet_ntoa(dst_sin.sin_addr));
					perror("send() failed at unspec2");
					exit(0);
				} else {
				    l_st->dec_send_pkt++;		 
                }
#endif
            }
            i++;
	    }
	}
      close_rtc(rtc);
     
      /* init send value */
      /* 送信バッファの初期化 */
	for(i=0;i < b_size - NROOTS;i++)
	{
		memset(outbuf.bf[i+send].buf, 0, MAXBUFSIZE);
		outbuf.bf[i+send].size = 0;
	}

	for(i = 0;i < b_size;i++){
		outbuf.bf[i+send].ts=0;
	}

      /* rsbuf set */
    /* メディアパケットの受信 */
	for(inbuf.head = 0;inbuf.head < b_size - nroots;inbuf.head++)
	{
		/* receive success */
		if(inbuf.bf[inbuf.head+fecsnbase].status)
	    { 
			/* inbuf -> rsbuf */
			if(MM == 4)
			{
		  		for(inbuf.tail = 0;inbuf.tail < MAXRSSIZE - 8;inbuf.tail++)
		    	{
		      		rsbuf.bf[inbuf.tail*2][inbuf.head] =
					(inbuf.bf[inbuf.head+fecsnbase].buf[inbuf.tail+gwhdr_size+8] >> 4) & 0x0f;
		      		rsbuf.bf[inbuf.tail*2+1][inbuf.head] =
					inbuf.bf[inbuf.head+fecsnbase].buf[inbuf.tail+gwhdr_size+8] & 0x0f;
		    	}
			}else if(MM == 8){
		  
		  		for(inbuf.tail = 0;inbuf.tail < MAXRSSIZE - 8;inbuf.tail++)
		    	{
					rsbuf.bf[inbuf.tail][inbuf.head] =
					inbuf.bf[inbuf.head+fecsnbase].buf[inbuf.tail+gwhdr_size+8];
		    	}    
			}
		}
	  else 
	    {
			/* receive failed */
			rsbuf.eras_pos[rsbuf.no_eras++] = inbuf.head;
		}
	}
		gettimeofday(&sect[2], NULL);
    /* FECパケットの受信 */
	for(inbuf.head = b_size - nroots;inbuf.head < b_size;inbuf.head++)
	{
		/* receive success */
		if(inbuf.bf[inbuf.head+fecsnbase].status)
		{ 
			/* inbuf -> rsbuf */
            /* RSバッファへパケットをコピー */
			if(MM == 4)
			{
				for(inbuf.tail = 0;inbuf.tail < MAXRSSIZE - 8;inbuf.tail++)
				{
					rsbuf.bf[inbuf.tail*2][inbuf.head] =
					(inbuf.bf[inbuf.head+fecsnbase].buf[inbuf.tail+gwhdr_size+8] >> 4) & 0x0f;
					rsbuf.bf[inbuf.tail*2+1][inbuf.head] =
					inbuf.bf[inbuf.head+fecsnbase].buf[inbuf.tail+gwhdr_size+8] & 0x0f;
		    	} 
			}else if(MM == 8){
		  		for(inbuf.tail = 0;inbuf.tail < MAXRSSIZE - 8;inbuf.tail++)
		    	{
					rsbuf.bf[inbuf.tail][NN -b_size + inbuf.head] =
					inbuf.bf[inbuf.head+fecsnbase].buf[inbuf.tail+gwhdr_size+8];
		    	}    
			}
		}
	  	else 
	    {
	        /* receive failed */
            /* パケットが損失していた場合 */
	      rsbuf.eras_pos[rsbuf.no_eras++] = inbuf.head;
	      fec_loss++;
	    }
	}

	loss_num = rsbuf.no_eras - fec_loss;
       
	/* rs decode process */
      
	/* recovery enable */
	gettimeofday(&sect[3], NULL);
		  
#if TIME_VERBOSE
	if(rsbuf.no_eras <= NROOTS )
#else
    /* パケット損失数が回復可能な数の場合はデコードフェーズへ */
	if(rsbuf.no_eras <= NROOTS && rsbuf.no_eras != 0)
//	if(rsbuf.no_eras <= NROOTS)
#endif
	{
		for(i = 0,ncorrect = 0;i < MAXRSSIZE * 2;i++)
		{
	      //printf("%d < %d loss %d\n", rsbuf.no_eras, NROOTS, l_st->second_loss);
          /* RSデコード処理 */
#if CCSDS
	      ncorrect = DECODE_RS(rsbuf.bf[i], rsbuf.eras_pos, rsbuf.no_eras, 0);
#else
          /* DECODE_RS(RS構造体のポインタ，バッファのポインタ,エラー箇所，エラー数) */ 
	      ncorrect = DECODE_RS(rs, rsbuf.bf[i], rsbuf.eras_pos, rsbuf.no_eras);
#endif
		/*for(j = 0;j < rsbuf.no_eras;j++){
	        printf("%d  ", rsbuf.eras_pos[j]);
		}*/
	      //printf("\n");
            /* デコードに失敗した場合 */
            if(ncorrect < 0)
			{
				loss_flag=1;
				printf("DECODE ERROR %d\n",i);
			}

			reco_num = (ncorrect>reco_num) ? ncorrect : reco_num;
		}
	   	
		for(inbuf.head = 0;inbuf.head < b_size - NROOTS;inbuf.head++)
	    {
			if(inbuf.bf[inbuf.head+fecsnbase].status == 0)
			{
				inbuf.bf[inbuf.head+fecsnbase].status = 1;
				/* recover recvsize */
				if(MM == 4){
					inbuf.bf[inbuf.head+fecsnbase].size = 
			  		(rsbuf.bf[4][inbuf.head] << 12 & 0xf000) 
			  		| (rsbuf.bf[5][inbuf.head] << 8 & 0x0f00) 
			  		| (rsbuf.bf[6][inbuf.head] << 4 & 0x00f0) 
			  		| (rsbuf.bf[7][inbuf.head] & 0x000f);
				} else if(MM == 8){
					inbuf.bf[inbuf.head+fecsnbase].size = 
					((rsbuf.bf[2][inbuf.head] << 8 & 0xff00) 
			   		| (rsbuf.bf[3][inbuf.head] & 0x00ff));
				}
				inbuf.bf[inbuf.head+fecsnbase].size 
				  = inbuf.bf[inbuf.head+fecsnbase].size + gwhdr_size + fechdr_size;
			}
		}
	} else {
		/* recovey unenable */
        /* 回復不可能な場合 */
		loss_flag = 1;
	}

	reco_num = reco_num - fec_loss;
	gettimeofday(&sect[4], NULL);
     
	if(loss_flag == 1){
		reco_num = 0;
	}
   
	l_st->loss_pkt += loss_num;
	l_st->recover_pkt += reco_num;

	/* output value set */
	for(inbuf.head = 0;inbuf.head < b_size;inbuf.head++)
	{
	  outbuf.bf[inbuf.head+fecsnbase].status = inbuf.bf[inbuf.head+fecsnbase].status;
	  outbuf.bf[inbuf.head+fecsnbase].size = inbuf.bf[inbuf.head+fecsnbase].size - gwhdr_size - fechdr_size;
	}

	if(outbuf.bf[inbuf.head+fecsnbase].size < 0){
		outbuf.bf[inbuf.head+fecsnbase].size = 0;
	}

	/* output buffer set */
	for(outbuf.head = 0;outbuf.head < b_size - NROOTS;outbuf.head++)
	{
	  /* rsbuf -> outbuf */
	  if(MM == 4){
	    for(outbuf.tail = 0;outbuf.tail < MAXPLSIZE * 2;outbuf.tail += 2)
	    {
	      outbuf.bf[outbuf.head+fecsnbase].buf[outbuf.tail/2] = 
		  ((rsbuf.bf[outbuf.tail+8][outbuf.head] << 4) & 0xf0) | (rsbuf.bf[outbuf.tail+9][outbuf.head] & 0xf);
	    }
	  } else if(MM == 8){
		for(outbuf.tail = 0;outbuf.tail < MAXPLSIZE ;outbuf.tail ++)
	    {
	      outbuf.bf[outbuf.head+fecsnbase].buf[outbuf.tail] = 
		  	(rsbuf.bf[outbuf.tail + 4][outbuf.head] & 0xff);
	    }
	  }
	}

	total_size = 0;
      /* init value */
      for(i=0;i < MAXPKT;i++)
	{
        memset(inbuf.bf[i].buf, 0, MAXBUFSIZE);
        inbuf.bf[i].status = 0;
        total_size += inbuf.bf[i].size;
        inbuf.bf[i].size = 0;
	}
    
    for(i = 0;i < MAXRSSIZE * 2;i++){
        memset(rsbuf.bf[i], 0, NN);      
    }

    for(i = 0;i < NN;i++) {
        rsbuf.eras_pos[i] = 0;
    }

    ncorrect = 0;

    gettimeofday(&sect[5], NULL);

    sum_ts = 0;
    fec_loss = 0;
    loss_num = 0;
    reco_num = 0;
    loss_flag = 0;

    /* recvbuf -> inbuf */
#if TH
    memcpy(&gwhdr, dec_recv_buf->bf[dec_recv_buf->head].buf, gwhdr_size);
    memcpy(&fechdr, dec_recv_buf->bf[dec_recv_buf->head].buf + gwhdr_size, fechdr_size);
#else
    memcpy(&gwhdr, recvbuf, gwhdr_size);
    memcpy(&fechdr, recvbuf + gwhdr_size, fechdr_size);
#endif 
    seq = ntohs(gwhdr.seq);
    snbase = ntohs(fechdr.snbase);
    fecseq = seq % b_size;
    fecsnbase = snbase % (b_size * 3);  
    outbuf.bf[fecseq + fecsnbase].ts=ntohl(gwhdr.timestamp);
      
    memcpy(inbuf.bf[fecseq + fecsnbase].buf, recvbuf, recvsize);
     
    inbuf.bf[fecseq + fecsnbase].size = recvsize;
    inbuf.bf[fecseq + fecsnbase].status = 1;
      
    /* send value set */
    send = fecsnbase - b_size;
    if(send < 0){
        send = b_size * 2;
    }

    gettimeofday(&end, NULL);
#if TIME_VERBOSE
		all = e_time("\nALL:",&sect[0], &end);
//		e_time(" +- Recv",&sect[0], &sect[1]);
//		e_time(" +- in->rs1",&sect[1], &sect[2]);
//		e_time(" +- in->rs2",&sect[2], &sect[3]);
		buf = e_time(" +- buff",&sect[0], &sect[3]);
		dec = e_time(" +- decode",&sect[3], &sect[4]);
		sprintf(fname,"dec-%d%d.txt",b_size,ds);
		if(count > 10 && count < 10000 && all > 0.0){
		if(rsbuf.no_eras <= (b_size - ds)){
		printf("%d %d\n",rsbuf.no_eras ,b_size - ds);
				s_all += all;
				s_buf += buf;
				s_dec += dec;
			fprintf(fp,"%.3f %.3f %.3f %d\n",s_all/(count - 10),s_buf/(count - 10),s_dec/(count - 10),total_size);
			printf("%.3f %.3f %.3f %d\n",s_all/(count - 10),s_buf/(count - 10),s_dec/(count - 10),seq);
		} else {
				count--;
		}
		} else if (count == 0){
				fp = fopen(fname,"w");
		} else if (count > 10000){
				puts("finished!");
				fclose(fp);
				exit(1);
		}
			count++;
//		e_time(" +- init",&sect[4], &sect[5]);
//		e_time(" +- post_init",&sect[5], &end);
#endif
      rsbuf.no_eras = 0;
    }
}
