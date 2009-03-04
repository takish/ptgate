#include "includes.h"
#include "filter_frame.h"

#define DENY 0
#define ALLOW 1
#define MCAST_ALLOW 2
#define UNIT 4

#define OCTET_BITS 16
#define OCTET_UNIT 5

#define MATCH_QUEUE 50
#define v4MASK 0xffffffff

static int deny(int code){
//    printf("DENY: %d\n", code);
    return DENY;
}

static int allow(int code){
//    printf("ALLOW: %d\n", code);
    return ALLOW;
}

static int m_allow(int code){
//    printf("MCAST_ALLOW: %d\n", code);
    return MCAST_ALLOW;
}

int filter_frame(u_char *buffer, session_t *sp)
{
    struct ethhdr *eth;
    struct iphdr *iph;
    struct ip6_hdr *ipv6h;
    struct udphdr *udph;
    struct tcphdr *tcph;
    struct icmp *icmph;
    char meth[3];
    struct in_addr insaddr,indaddr;
    struct in6_addr in6src,in6dst;
    int cnt, i;
    char dest[20];
    enum layer3 {ipv4, ipv6} NET_PROTO;
    enum layer4 {tcp, udp} TRANS_PROTO;
    static u_int32_t last_tcpseq, tcpseq;
    static u_int16_t last_icmpseq, icmpseq;
    char src_addr6[40], dst_addr6[40];

    eth = (struct ethhdr *)buffer;

//    printf("%x %d %x %x\n",sp->destnet, sp->destmask, sp->network, (inet_addr(DEST_NET)));
    /* IP layer process */
    if(ntohs(eth->h_proto) == ETH_P_IP){
        NET_PROTO = ipv4;
        iph = (struct iphdr *)(buffer+sizeof(struct ethhdr));
    } else if(ntohs(eth->h_proto) == ETH_P_IPV6){
//        return deny(500);
        NET_PROTO = ipv6;
        ipv6h = (struct ip6_hdr *)(buffer+sizeof(struct ethhdr));
    } else {
        /* Receive unsupporting protocol */
        return deny(400);
    }
#if 0
    /* Transport layer process */
    if(NET_PROTO == ipv4){
        if(iph->protocol == IPPROTO_TCP){
        } else if(iph->protocol == IPPROTO_UDP){
                udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + iph->ihl*UNIT);
            printf("%d\n", ntohs(udph->len));
        }
    }
#endif
#if 1
    /* Transport layer process */
    if(NET_PROTO == ipv4){
        if(iph->protocol == IPPROTO_TCP){
            /* フラグメントしていない時 */
            if((htons(iph->frag_off) & IP_OFFMASK) == 0){
                tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + iph->ihl*UNIT);
//            last_tcpseq = tcpseq;
//            tcpseq = tcph->seq;
                TRANS_PROTO = tcp;
            }
        } else if(iph->protocol == IPPROTO_UDP){
            /* フラグメントしていない時 */
            if((htons(iph->frag_off) & IP_OFFMASK) == 0){
                udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + iph->ihl*UNIT);
                TRANS_PROTO = udp;
            }
        } else if(iph->protocol == IPPROTO_ICMP){
            icmph = (struct icmp *)(buffer+sizeof(struct ethhdr)+iph->ihl*UNIT);
//            last_icmpseq = icmpseq;
//            icmpseq = icmph->icmp_seq;
//            if(last_icmpseq == icmpseq){
//                    return deny(2);
//            }
            TRANS_PROTO = 98;
        } else {
            TRANS_PROTO = 99;
        /* Do Nothing */
//   return deny();
        }
    } else if(NET_PROTO == ipv6){
        in6src = ipv6h->ip6_src;
        in6dst = ipv6h->ip6_dst;

        if(ipv6h->ip6_nxt == IPPROTO_TCP){
            tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
            TRANS_PROTO = tcp;
        } else if(ipv6h->ip6_nxt == IPPROTO_UDP){
            udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
            TRANS_PROTO = udp;
        } else {
            TRANS_PROTO = 99;
        }
    } else {
        NET_PROTO = 99;
    }

    /* Filtering Rule */
    /* avoid well-known port */
//    printf("%d %x\n", iph->id, htons(iph->frag_off)&(IP_OFFMASK) );
    if((TRANS_PROTO == udp) && (udph != NULL)){
        assert(udph != NULL);
        for(i = 0;i < sp->d_port_cnt;i++){
            if(ntohs(udph->dest) == sp->d_port[i]){
                return deny(412);
            }
        }
/*  if(ntohs(udph->dest) < 1024){
            return deny(410);
  }
  if(ntohs(udph->source) < 1024){
   return deny(411);
  }
  if(ntohs(udph->dest) == 9004){
   return deny(412);
  }
  if(ntohs(udph->source) == 9004){
   return deny(413);
  }
*/
    }

    if((TRANS_PROTO == tcp) && (tcph != NULL)){
/*  if(last_tcpseq == tcpseq){
//   return deny(4);
  }
  if(ntohs(tcph->dest) == 22){
   return deny(422);
  }
  if(ntohs(tcph->source) == 22){
   return deny(422);
  }
  if(ntohs(tcph->dest) == 20){
   return allow(220);
  }
  if(ntohs(tcph->dest) == 21){
   return allow(220);
  }
  if(ntohs(tcph->dest) == 80){
   return allow(220);
  }
  if(ntohs(tcph->dest) < 1024){
   return deny(420);
  }
  if(ntohs(tcph->source) < 1024){
   return deny(421);
  }
        */
 }
// packet_dump(buffer);
#endif

    if(NET_PROTO == ipv4){
        /*
  for(cnt = 0; cnt < sp->session_num; cnt++){
   sprintf(dest,"%s",sp->ESendAddr[cnt]);
   // avoid correspond node 
   if(iph->saddr == inet_addr(dest)){
    return deny(431);
   }
  }
    */

    /* basic ipv4 filter rule */
    /* avoid broadcast packet */
//        printf("%x\n",sp->netmask^v4MASK);
//  if(((ntohl(iph->daddr)&0xff)) == 0xff){
    if(((ntohl(iph->daddr)&(sp->netmask^v4MASK))) == (sp->netmask^v4MASK)){
        return deny(430);
    }

    /* avoid sending packet */
//printf("%x %x\n", ntohl(sp->hostip), (iph->saddr));
    if(ntohl(sp->hostip) == (iph->saddr)){
        return deny(432);
    }

    /* avoid incoming packet */
    if((sp->hostip) == (iph->daddr)){
        return deny(433);
    }

/*        if((inet_addr(sp->localnet)&(NETMASK[24].mask)) == (iph->daddr&(NETMASK[24].mask))){
            return deny(7);
        }
        */

    /* For Multicast */
    /* Multicastパケットの場合 */
    if(IN_MULTICAST(ntohl(iph->daddr))){
        /* 他ネットワークからのマルチキャストパケットの場合 */
        if(sp->m_taddr){
/*            if(iph->saddr == sp->m_taddr){
                return m_allow(200);
            }
*/
        }
        /* 送信パケットが自ネットワークのもの以外は拒否 */
        if(sp->network != (iph->saddr&ntohl(sp->netmask))){
//   if((inet_addr(sp->localnet)&(NETMASK[24].mask)) != (iph->saddr&(NETMASK[24].mask))){
            return deny(440);
        }
        /* Avoid local multicast loop */
//   if(inet_addr(sp->localnet) == inet_addr(DEST_NET)){
//   if(sp->network == inet_addr(DEST_NET)){
        /* 自ネットワークと宛先が同じマルチキャストパケットを拒否 */
        /* これはパケットを見ていないんで意味がないかも */
#if 0
        if(sp->network == sp->destnet){
            return deny(441);
        }
#endif
        return m_allow(200);
    }

    if((sp->destnet&(NETMASK[sp->destmask].mask)) == (iph->daddr&(NETMASK[sp->destmask].mask))){
        if(sp->network == (iph->saddr&ntohl(sp->netmask))){
//   if((inet_addr(sp->localnet)&(NETMASK[24].mask)) == (iph->saddr&(NETMASK[24].mask))){
//   if((inet_addr(LOCAL_NET)&(NETMASK[24].mask)) == (iph->saddr&(NETMASK[24].mask))){
            return allow(230);
        }
    }

    } else if(NET_PROTO == ipv6){
  /* For Multicast */
//  IN6_IS_ADDR_MULTICAST
/*  if(ntohs(in6dst.s6_addr16[0]) == 0xff02){
   return m_allow(300);
  }
*/
        sprintf(dst_addr6, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
                ntohs(in6dst.s6_addr16[0]),
                ntohs(in6dst.s6_addr16[1]),
                ntohs(in6dst.s6_addr16[2]),
                ntohs(in6dst.s6_addr16[3]),
                ntohs(in6dst.s6_addr16[4]),
                ntohs(in6dst.s6_addr16[5]),
                ntohs(in6dst.s6_addr16[6]),
                ntohs(in6dst.s6_addr16[7])
                );
        sprintf(src_addr6, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
                ntohs(in6src.s6_addr16[0]),
                ntohs(in6src.s6_addr16[1]),
                ntohs(in6src.s6_addr16[2]),
                ntohs(in6src.s6_addr16[3]),
                ntohs(in6src.s6_addr16[4]),
                ntohs(in6src.s6_addr16[5]),
                ntohs(in6src.s6_addr16[6]),
                ntohs(in6src.s6_addr16[7])
                );

//        printf("%s -> %s\n",src_addr6, dst_addr6);
        if((ntohs(in6dst.s6_addr16[0])&0xfff0) == 0xff10){
//      if(ntohs(in6dst.s6_addr16[0]) == 0xff1e){
//printf("host %s src %s\n", sp->hostip6, src_addr6);
            /* 送信先が自ネットワークのもののみ送出 */
            if(strncmp(sp->hostip6, src_addr6, sp->prefix/OCTET_BITS*OCTET_UNIT) == 0)
            {
                return m_allow(301);
            }

            /* マルチキャスト転送オプションがセットされている場合 */
            if(sp->m_taddr6){
                if(strncmp(sp->m_taddr6, src_addr6, sp->prefix/OCTET_BITS*OCTET_UNIT) == 0)
                {
                    return m_allow(301);
                }
            }

            /* 送信元がリンクローカルアドレスでも送出 */
            if(ntohs(in6src.s6_addr16[0]) == 0xfe80){
                return m_allow(302);
            }

            return deny(533);
/*          if(ntohs(in6src.s6_addr16[2]) != 0x5102){
                return deny(530);
            }
            return m_allow(300);
*/
        }
    }
    return deny(499);
}

int packet_dump(u_char *buffer){
    printf("\n");
    ip_dump(buffer);
    trans_dump(buffer);
    printf("\n");
}

int ip_dump(u_char *buffer){
    struct ethhdr *eth;
    eth = (struct ethhdr *)(buffer);

    if(ntohs(eth->h_proto) == ETH_P_IP){
        ip4_dump(buffer);
        return TRUE;
    }else if(ntohs(eth->h_proto) == ETH_P_IPV6){
        ip6_dump(buffer);
        return TRUE;
    }

    return FALSE;
}

int trans_dump(u_char *buffer){
    struct iphdr *iph;
    iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    if(iph->protocol == IPPROTO_UDP){
        udp_dump(buffer);
        return TRUE;
    } else if(iph->protocol == IPPROTO_TCP){
        tcp_dump(buffer);
        return TRUE;
    } else if(iph->protocol == IPPROTO_ICMP){
        icmp_dump(buffer);
        return TRUE;
    } else {
        printf("unsupport protocol\n");
        return FALSE;
    }
}

int ip4_dump(u_char *buffer){

    struct iphdr *iph;
    struct in_addr insaddr,indaddr;

    iph = (struct iphdr *)(buffer+sizeof(struct ethhdr));

    insaddr.s_addr = iph->saddr;
    indaddr.s_addr = iph->daddr;

    printf("IP  :ver|ihl|tos|totlen|id|frag_off|ttl|proto|check|\t");
    printf("SRC: %s \n",inet_ntoa(insaddr));
    printf("    :%3u|%3u|%3u|%6u|%2u|%8u|%3u|%5u|%5u|\t",
        iph->version,iph->ihl,iph->tos,
        ntohs(iph->tot_len),
        ntohs(iph->id),
        ntohs((iph->frag_off) & 8191),
        iph->ttl,
        iph->protocol,
        ntohs(iph->check));
        printf("DST: %s\n",inet_ntoa(indaddr));

    return TRUE;
}

int ip6_dump(u_char *buffer){
    struct ip6_hdr *ipv6h;
    struct in6_addr in6src,in6dst;

    ipv6h = (struct ip6_hdr *)(buffer+sizeof(struct ethhdr));

    in6src = ipv6h->ip6_src;
    in6dst = ipv6h->ip6_dst;

    printf("%08x:",ntohl(in6dst.s6_addr32[0]));
    printf("%08x:",ntohl(in6dst.s6_addr32[1]));
    printf("%08x:",ntohl(in6dst.s6_addr32[2]));
    printf("%08x\n",ntohl(in6dst.s6_addr32[3]));

    return TRUE;
}

int icmp_dump(u_char *buffer){
    struct iphdr *iph;
    struct icmp *icmph;
// icmph = (struct icmp *)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr));
    iph = (struct iphdr *)(buffer+sizeof(struct ethhdr));
    icmph = (struct icmp *)(buffer+sizeof(struct ethhdr)+iph->ihl*UNIT);

    printf("ICMP:type|code| id | seq |\n");
    printf("    :%4x|%4x|%4x|%5x|\n",
        (icmph->icmp_type), (icmph->icmp_code), 
        (icmph->icmp_id), (icmph->icmp_seq));

    return TRUE;
}

int udp_dump(u_char *buffer){
    struct iphdr *iph;
    struct udphdr *udph;

    iph = (struct iphdr *)(buffer+sizeof(struct ethhdr));
//  udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + iph->ihl*UNIT);

    printf("UDP :src_port|dst_port|length|\n");
    printf("    :%8u|%8u|%6u|\n",ntohs(udph->source), ntohs(udph->dest) ,ntohs(udph->len));

    return TRUE;
}

int tcp_dump(u_char *buffer){
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = (struct iphdr *)(buffer+sizeof(struct ethhdr));
//  tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + iph->ihl*UNIT);

//  printf("----TCP Header-------------------\n");
    printf("TCP :src_port|dst_port|   seq    |   ack    |window|check |urt_prt|frags\n");
    printf("    :%8d|%8d|%8u|%10u|%10u|0x%4x|%7u|",
        ntohs(tcph->source), ntohs(tcph->dest),
        ntohl(tcph->seq), ntohl(tcph->ack_seq),
        ntohs(tcph->window), ntohs(tcph->check),
        tcph->urg_ptr
    );
    tcph->fin ? printf(" FIN") : 0 ;
    tcph->syn ? printf(" SYN") : 0 ;
    tcph->rst ? printf(" RST") : 0 ;
    tcph->psh ? printf(" PSH") : 0 ;
    tcph->ack ? printf(" ACK") : 0 ;
    tcph->urg ? printf(" URG") : 0 ;
    printf("\n");

/* printf("source port : %u\n",ntohs(tcph->source));
 printf("dest port   : %u\n",ntohs(tcph->dest));
 printf("sequence    : %u\n",ntohl(tcph->seq));
 printf("ack seq     : %u\n",ntohl(tcph->ack_seq));
 printf("frags       :");
 tcph->fin ? printf(" FIN") : 0 ;
 tcph->syn ? printf(" SYN") : 0 ;
 tcph->rst ? printf(" RST") : 0 ;
 tcph->psh ? printf(" PSH") : 0 ;
 tcph->ack ? printf(" ACK") : 0 ;
 tcph->urg ? printf(" URG") : 0 ;
 printf("\n");
 printf("window      : %u\n",ntohs(tcph->window));
 printf("check       : 0x%x\n",ntohs(tcph->check));
 printf("urt_ptr     : %u\n\n\n",tcph->urg_ptr);
*/

    return TRUE;
}

/* IPヘッダのバージョンを判定 */
int v4orv6(u_char *buffer){
    struct iphdr *iph;

    iph = (struct iphdr *)buffer;

    if(iph->version == 4) {
        return iph->version;
    } else if (iph->version == 6){
        return iph->version;
    }
    return FALSE;
}

/* UDPパケットか否かを判定 */
int find_udp(u_char *buffer){
    struct iphdr *iph;
    struct ip6_hdr *ipv6h;
    int version;

    version = v4orv6(buffer);

    if(version == 4){
        iph = (struct iphdr *)buffer;

        if(iph->protocol == IPPROTO_UDP){
            return TRUE;
        }
    } else if(version == 6){
        ipv6h = (struct ip6_hdr *)buffer;

        /* フラグメントヘッダや他ヘッダの場合は冗長化されない */
        /* 要修正？ */
        if(ipv6h->ip6_nxt == IPPROTO_UDP){
            return TRUE;
        } 
    }

    return FALSE;
}

/* RAWソケットの書き出しパケットをフィルタする */
int filter_src_net(struct iphdr *iph, session_t *sp){
    if((sp->destnet&(NETMASK[sp->destmask].mask)) == (iph->saddr&(NETMASK[sp->destmask].mask))){
//      printf("Filtnet:%x %x\n",sp->destnet, sp->destmask);
        return FALSE;
    }
    return TRUE;
}

 int filter_src_host(struct iphdr *iph, session_t *sp){
    if(ntohl(sp->hostip) == (iph->saddr)){
        return FALSE;
    }
    return TRUE;
}

 int filter_dst_host(struct iphdr *iph, session_t *sp){
//            printf("Filthost:%x %x\n",ntohl(sp->hostip), iph->daddr);
    if(ntohl(sp->hostip) == (iph->daddr)){
       return FALSE;
    }
    return TRUE;
}

/* 送信元MACアドレスでフィルタ */
int filter_mac_src(u_char *buffer, session_t *sp){
    struct ethhdr *eth;
    int ret;

    eth = (struct ethhdr *)buffer;
  
    ret = memcmp(eth->h_source, sp->mac, ETH_ALEN);
    if(ret == 0){
//        print_mac_addr(buffer);
        return TRUE;
    }

    return FALSE;
}

/* MACアドレスを出力 */
int print_mac_addr(u_char *buffer){
    struct ethhdr *eth;

    eth = (struct ethhdr *)buffer;

    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
       eth->h_source[0],
       eth->h_source[1],
       eth->h_source[2],
       eth->h_source[3],
       eth->h_source[4],
       eth->h_source[5]);

    return TRUE;
}

int filter_src(u_char *buffer, session_t *sp){
    struct iphdr *iph;
    struct ip6_hdr *ipv6h;
    struct ethhdr *eth;
    int version;

    eth = (struct ethhdr *)buffer;

// ip_dump(buffer);
    /* IP layer process */
    if(ntohs(eth->h_proto) == ETH_P_IP){
        iph = (struct iphdr *)(buffer+sizeof(struct ethhdr));
        version = 4;
    } else if(ntohs(eth->h_proto) == ETH_P_IPV6){
        ipv6h = (struct ip6_hdr *)(buffer+sizeof(struct ethhdr));
        version = 6;
    } else {
        return FALSE;
    }
 

 //           printf("IN:%x %x\n",ntohl(sp->hostip), iph->saddr);
//    printf("%d\n",version);
    if(version == 4){
    /* basic ipv4 filter rule */
    /* avoid broadcast packet */
        if(((ntohl(iph->daddr)&0xff)) == 0xff){
            return deny(430);
        }

        /* avoid sending packet */
//      printf("%x %x\n", ntohl(sp->hostip), (iph->saddr));
        if(ntohl(sp->hostip) == (iph->saddr)){
//          printf("NG:%x %x\n",ntohl(sp->hostip), iph->saddr);
            return deny(432);
        }

/*      if((sp->destnet&(NETMASK[sp->destmask].mask)) == (iph->saddr&(NETMASK[sp->destmask].mask))){
            printf("Filtnet:%x %x\n",sp->destnet, sp->destmask);
            return FALSE;
        }
        */

        return filter_src_net(iph, sp);

        /* avoid incoming packet */
        if((sp->hostip) == (iph->daddr)){
            return deny(433);
        }

    } else if(version == 6){

    } else {
        printf("unknown ip version: filt");
        return FALSE;
    }

//   printf("OK:%x %x\n",ntohl(sp->hostip), iph->saddr);
    return TRUE;
}

/* IPパケットを判別 */
int ip_sifter(u_char *buffer){
    int ret;

    ret = mac_type(buffer);

    if(ret == FALSE){
        return FALSE;
    } else {
        return TRUE;
    }
    /* NOT REACHED */
}

/* 上位プロトコルタイプを判別 */
int mac_type(u_char *buffer){
    struct ethhdr *eth;

    eth = (struct ethhdr *)buffer;

//    printf("0x%04x\n",ntohs(eth->h_proto));
    if(ntohs(eth->h_proto) == ETH_P_IP){
        return ETH_P_IP;
    } else if(ntohs(eth->h_proto) == ETH_P_IPV6){
        return ETH_P_IPV6;
    } else {
        return FALSE;
    }
}

#if 0
/* RAWソケットで書き出したパケットをフィルタ */
int filter_sent_pkt(u_char *buffer, int bufsize){
//    typedef u_char buf_t[2000];
//    static buf_t buffer_last[MATCH_QUEUE];
    static u_char buffer_last[MATCH_QUEUE][2000];
    int ret, j;
    static int i = 0;

    for(j = 0; j < MATCH_QUEUE; j++){
        ret = memcmp(buffer, &buffer_last[j], bufsize);
        printf("%d\n",ret);
        if(ret == 0){
            break;
        }
    }
//    buffer_last[i] = *buffer;
    memcpy(&buffer_last[i][0], buffer, bufsize);


//    ip_dump(buffer);
//        printf("%d %d %d\n",ret, iph_sent.check,iph_last.check);
    i++;

    if(i == MATCH_QUEUE){
        i = 0;
    }

    if(ret == 0){
        return FALSE;
    } else {
        return TRUE;
    }
}
#endif

#if 1
/* RAWソケットで書き出したパケットをフィルタ */
/* もういらないかも */
int filter_sent_pkt(struct iphdr *iph){
    static struct iphdr iph_last[MATCH_QUEUE];
    int ret, j;
    static int i = 0;

//    printf("%d\n",memcmp(iph, &iph_sent, sizeof(struct iphdr)));
    for(j = 0; j < MATCH_QUEUE; j++){
        ret = memcmp(iph, &iph_last[j], sizeof(struct iphdr));
        if(ret == 0){
            break;
        }
    }
//    iph_last[i] = iph_sent;
    memcpy(&iph_last[i], iph, sizeof(struct iphdr));

//    ip_dump(buffer);
//        printf("%d %d %d\n",ret, iph_sent.check,iph_last.check);
    i++;

    if(i == MATCH_QUEUE){
        i = 0;
    }

    if(ret == 0){
        return FALSE;
    } else {
        return TRUE;
    }
}
#endif
