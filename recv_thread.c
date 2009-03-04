#include "includes.h"
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <linux/types.h>
#include <linux/filter.h>
#include <netpacket/packet.h>
//int s_sock;

#if 0
void recover_handler(int n){
//    recover_from_promisc(s_sock, INTERFACE);
    recover_from_promisc2(INTERFACE);
    exit(0);
}
#endif

/* ENC受信用スレッド */
PUBLIC void *ENC_RX_Loop_Thread(session_t *sp)
{
    u_char recvbuf[MAXBUFSIZE];
    int recvsize;
    struct ip_mreq multicastRequest;
    int sock_buflen = SOCK_BUFLEN;
    char flag = 0;
    socklen_t your_adlen;
//    struct addrinfo hints;
//    int length = sizeof(hints);
    struct sockaddr_ll from;
    socklen_t   fromlen = sizeof(from);
    int filter = 0;
    int filter_mac = 0;
    int s_sock;
    int t_sock, t_sock6;
    fd_set  fds;

//    int th_sock;
    struct sockaddr_in dst_sin;
    struct iphdr *iph;
    int udp_flag;
//    signal(SIGINT, recover_handler);

    pthread_detach(pthread_self());

/*    if((th_sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) == -1){
        perror("socket");
        exit(1);
    }
    */

#if RAW
    /* 通過用RAWソケット */
    t_sock = send_raw_sock_create();
    /* 通過用RAWソケット、まだ未使用：IPv6が有効な場合 */
    if(sp->enable_ipv6){
        t_sock6 = send_raw_sock6_create();
    }
//    s_sock = recv_raw_sock_create(INTERFACE);
    /* 受信用RAWソケット */
    s_sock = raw_sock_create(INTERFACE, 1);

#if ENABLE_BPF
    /*
     * tcpdump \(src net 192.168.1.0/24\) and \(dst host 165.242.42.206\) -dd
     */
    struct sock_filter BPF_code[] = {
#if 0
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 5, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        /* Netmask */
        { 0x54, 0, 0, sp->netmask },
        /* src network */
        { 0x15, 0, 10, sp->network },
        { 0x20, 0, 0, 0x0000001e },
        /* dst host */
        { 0x15, 8, 7, inet_addr(sp->ESendAddr[0].addr) },
        { 0x15, 1, 0, 0x00000806 },
        { 0x15, 0, 6, 0x00008035 },
        { 0x20, 0, 0, 0x0000001c },
        /* Netmask */
        { 0x54, 0, 0, sp->netmask },
        /* src network */
        { 0x15, 0, 3, sp->network },
        { 0x20, 0, 0, 0x00000026 },
        /* dst host */
//        { 0x15, 2, 0, inet_addr(sp->ESendAddr[1].addr) },
        { 0x15, 1, 0, inet_addr(sp->ESendAddr[0].addr) },
        { 0x6, 0, 0, 0x00000060 },
        { 0x6, 0, 0, 0x00000000 }
#endif
#if 1
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 5, 0x00000800 },
        { 0x20, 0, 0, 0x0000001a },
        { 0x54, 0, 0, 0xffffff00 },
        { 0x15, 0, 10, 0xc0a80100 },
        { 0x20, 0, 0, 0x0000001e },
        { 0x15, 8, 7, 0xa5f22ace },
        { 0x15, 1, 0, 0x00000806 },
        { 0x15, 0, 6, 0x00008035 },
        { 0x20, 0, 0, 0x0000001c },
        { 0x54, 0, 0, 0xffffff00 },
        { 0x15, 0, 3, 0xc0a80100 },
        { 0x20, 0, 0, 0x00000026 },
        { 0x15, 1, 0, 0xa5f22ace },
        { 0x6, 0, 0, 0x00000060 },
        { 0x6, 0, 0, 0x00000000 }
#endif
    };

    struct sock_fprog Filter;

    Filter.len = 16;
    Filter.filter = BPF_code;

    /* Attach the filter to the socket */
#if 0
    if( setsockopt(s_sock, SOL_SOCKET, SO_ATTACH_FILTER, &Filter, sizeof(Filter)) < 0 ) {
        perror("setsockopt");
        close(s_sock);
        exit(EXIT_FAILURE);
    }
#endif
#endif
#else
    s_sock = recv_sock_create(NULL, sp->EServAddr.port, &your_adlen);

    if(sp->serv_group_e){
          multicastRequest.imr_multiaddr.s_addr = inet_addr(sp->serv_group_e);
          multicastRequest.imr_interface.s_addr = htonl(INADDR_ANY);
          if(setsockopt(s_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&multicastRequest, sizeof(multicastRequest)) < 0){
                  perror("JOIN failed");
          }
          if(setsockopt(s_sock, IPPROTO_IP, IP_MULTICAST_LOOP, &flag, sizeof(flag)) < 0){
                  perror("Set Loop failed");
          } 
    }
#endif

    FD_ZERO(&fds);
    FD_SET(s_sock, &fds);

    for(;;)
    {
    //        printf("%d \n",enc_recv_buf->tail - enc_recv_buf->head);

        if((enc_recv_buf->tail + 1) % MAX_RECVBUF_NUM == enc_recv_buf->head) {
            puts("recv_buffer is full");
        }
      
        if( select(s_sock + 1, &fds , NULL, NULL, NULL) < 0 ){
            perror("select");
            exit(0);
        }
    
        if (FD_ISSET(s_sock, &fds)){
        if((recvsize = recvfrom(s_sock, recvbuf, MAXPLSIZE, 0, (SA *)&from, &fromlen)) < 0) {
//        if((recvsize = recvfrom(s_sock, recvbuf, MAXPLSIZE, 0, (SA *)&hints, &length)) < 0) {
//        if((recvsize = recv(s_sock, recvbuf, MAXPLSIZE, 0)) < 0) {
          perror("recv() failed");
          exit(0);
        } 
//        printf("size:%d\n",recvsize);
//        e_point(&DIV[0]);
#if RAW
        /* 自分が送信したパケットを落とす */
        filter_mac = filter_mac_src(recvbuf, sp);

        if(filter_mac == 0){
            /* 転送条件に当てはまるか判定 */
            filter = filter_frame(recvbuf,sp);

            l_st->enc_recv_pkt++;
            l_st->enc_ring_pkt = enc_recv_buf->tail - enc_recv_buf->head;

            /* パターンに合致する場合 */
            if(filter == 1 || filter == 2){
        gettimeofday(&DIV[0], NULL);
        t3 = my_clock();

#endif
//      memcpy(&gwhdr,recvbuf,extsize);      
//      seq = gwhdr.seq;
//        recvsize = 1442;
//        printf("size:%d\n",recvsize);
            /* UDPかどうか判定 */
                udp_flag = find_udp(recvbuf + sizeof(struct ethhdr));

                /* UDPパケットの場合，スルーモードで起動していない場合 */
                if((udp_flag == TRUE) && (sp->through == 0)){
                    /* 冗長化フェーズへ */
                    memcpy(enc_recv_buf->bf[enc_recv_buf->tail].buf, 
                        recvbuf+sizeof(struct ethhdr), recvsize-sizeof(struct ethhdr));
                    enc_recv_buf->bf[enc_recv_buf->tail].size = 
                                recvsize-sizeof(struct ethhdr);
                    enc_recv_buf->bf[enc_recv_buf->tail].timestamp = t3;

                    enc_recv_buf->tail = ++enc_recv_buf->tail % MAX_RECVBUF_NUM;

                    /* エンコード用バッファのロック解除 */
                    pthread_cond_signal(&data_recv_enc);
            } else {
                /* 通過フェーズへ */
                memcpy(enc_th_buf->bf[enc_th_buf->tail].buf, 
                    recvbuf+sizeof(struct ethhdr), recvsize-sizeof(struct ethhdr));
                enc_th_buf->bf[enc_th_buf->tail].size = 
                    recvsize-sizeof(struct ethhdr);
                enc_th_buf->bf[enc_th_buf->tail].timestamp = t3; 

                enc_th_buf->tail = ++enc_th_buf->tail % MAX_RECVBUF_NUM;

                pthread_cond_signal(&data_recv_enc_th);
            } 
            
#if RAW
        } else if (sp->destnet) {
            /* デフォルトゲートウェイのとき */
            /* Filterに合致せずそのままパケットを転送する場合 */
//            send_packets2(t_sock, t_sock6, recvbuf+sizeof(struct ethhdr), recvsize);
            /* IPv4の場合 */
            /* IPv6の場合はまだ未作成 */
            /* 自分が送信したパケットをフィルタ */
            filter = filter_src(recvbuf, sp);
//            print_mac_addr(recvbuf);
            /* 自ホストが宛先のパケットをフィルタ */
            filter = (filter && filter_dst_host(recvbuf + sizeof(struct ethhdr), sp));

            /* IPパケットのみをフィルタ */
//            filter = ip_sifter(recvbuf);
//            printf("%x\n",mac_type(recvbuf));
            if(filter){
//                printf("%d\n",filter);
#if 1
                /* 前回書き出したパケットをフィルタ */
                /* おそらくもう必要ない */
//                filter = filter_sent_pkt(recvbuf + sizeof(struct ethhdr));
//                printf("FILT: %d\n",filter);

                if(filter){
                    memset(&dst_sin, 0, sizeof(dst_sin));
                    iph = (struct iphdr *)(recvbuf + sizeof(struct ethhdr));
                    dst_sin.sin_addr.s_addr = iph->daddr;
                    dst_sin.sin_family = AF_INET;

//                    ip_dump(recvbuf);
//                   /* IPパケットの送信 */
                    if(sendto(t_sock, recvbuf + sizeof(struct ethhdr),
                       ntohs(iph->tot_len), 0, 
//                       recvsize - sizeof(struct ethhdr), 0, 
                       (SA *)&dst_sin, sizeof(dst_sin)) == -1)
                    {
                        puts("ng");
                        printf("%s\n",inet_ntoa(dst_sin.sin_addr));
                        perror("send() failed at send_packets v4 th");
                        exit(0);
                    }

//                    l_st->enc_send_pkt++;
                    l_st->allow++;

                }
#endif
            }
        }
	}
#endif
    } 
    }
}

/* DEC受信用スレッド */
PUBLIC void *DEC_RX_Loop_Thread(session_t *sp)
{
    int sock;
    struct sockaddr_in ServAddr[3];
    u_char recvbuf[MAXBUFSIZE];
    int recvsize;
    struct ip_mreq multicastRequest;
    int sock_buflen = SOCK_BUFLEN;
    char flag = 0;
    socklen_t your_adlen;
    struct addrinfo hints;
    int length = sizeof(hints);
    gw_hdr gwhdr;
    /* for relay socket */
    int cnt;
    int r_sendsock[MAX_CLIENTS];
    socklen_t r_your_adlen;
    SA *r_your_addr[MAX_CLIENTS];

    pthread_detach(pthread_self());

    sock = recv_sock_create(NULL, sp->DServAddr.port, &your_adlen);

    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &sock_buflen, sizeof(sock_buflen));

    if(sp->serv_group_d){
          multicastRequest.imr_multiaddr.s_addr = inet_addr(sp->serv_group_d);
          multicastRequest.imr_interface.s_addr = htonl(INADDR_ANY);

          if(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&multicastRequest, sizeof(multicastRequest)) < 0){
              perror("JOIN failed");
          }
  }

    /* Relay用socket作成 */
    for(cnt = 0; cnt < sp->relay_num; cnt++){
        r_sendsock[cnt] = send_sock_create(sp->RSendAddr[cnt].addr, sp->RSendAddr[cnt].port, (void **)&r_your_addr[cnt], &r_your_adlen);

        setsockopt(r_sendsock[cnt], SOL_SOCKET, SO_SNDBUF, &sock_buflen, sizeof(sock_buflen));
    }
 
    for(;;)
    {
//            printf("%d %d\n",dec_recv_buf->tail, dec_recv_buf->head);
        /* リングバッファがいっぱいかどうかチェック */
        if((dec_recv_buf->tail + 1) % MAX_RECVBUF_NUM == dec_recv_buf->head) {
            puts("recv_buffer is full");
        }

        /* ENCからのパケットを受信 */
        if((recvsize = recvfrom(sock, recvbuf, MAXPLSIZE, 0, (SA *)&hints, &length)) < 0) {
            perror("recv() failed");
            exit(0);
        } 

        /* 中継する場合受け取った物をここでそのまま転送する */
        for(cnt = 0; cnt < sp->relay_num; cnt++){
            if(sendto(r_sendsock[cnt], recvbuf, recvsize, 0, r_your_addr[cnt], r_your_adlen) == -1)
            {
                perror("send() failed unspec : relay");
                exit(0);
            }
            l_st->relay_pkt++;
        }

        //e_point(&DIV[2]);
        gettimeofday(&DIV[2], NULL);
        t1 = my_clock();

        l_st->dec_ring_pkt = dec_recv_buf->tail - dec_recv_buf->head;
        memcpy(&gwhdr,recvbuf,sizeof(gwhdr));      
//      l_st->dec_recv_pkt++;
//      seq = gwhdr.seq;
//        printf("%d\n", gwhdr.pt);
      
        /* PTが34の場合，スルーモードで起動している場合 */
        if((gwhdr.pt == 34) || sp->through == 1){
            /* 通過フェーズへ */
            memcpy(dec_th_buf->bf[dec_th_buf->tail].buf, recvbuf, recvsize);
            dec_th_buf->bf[dec_th_buf->tail].size = recvsize;
            dec_th_buf->bf[dec_th_buf->tail].timestamp = t1;

            /* スルー用リングバッファのおしりを更新 */
            dec_th_buf->tail = ++dec_th_buf->tail % MAX_RECVBUF_NUM;

            /* パケットの受信をスルーバッファに教える */
            pthread_cond_signal(&data_recv_dec_th);

        } else {
            /* decodeフェーズへ */
            memcpy(dec_recv_buf->bf[dec_recv_buf->tail].buf, recvbuf, recvsize);
            dec_recv_buf->bf[dec_recv_buf->tail].size = recvsize;

            /* リングバッファのおしりを更新 */
            dec_recv_buf->tail = ++dec_recv_buf->tail % MAX_RECVBUF_NUM;

            /* パケットの受信を冗長化バッファに教える */
            pthread_cond_signal(&data_recv_dec);
        }
    }
}
