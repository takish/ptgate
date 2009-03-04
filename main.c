/*
 * $Date: 2005/01/25 11:57:52 $
 * $Id: main.c,v 1.37 2005/01/25 11:57:52 takashi Exp $
 * $Revision: 1.37 $
 */
#include "includes.h"
#include "asarray.h"
#include <syslog.h>
#include <linux/if.h>
#include <sys/ioctl.h>

//#include <curses.h>
#include <errno.h>

//#include "utilfcns.h"

/* ログの表示間隔 */
#define TIMEOUT_SEC 1
#define TIMEOUT_USEC 0
/* ステータスタイトルの間隔(sec) */
#define LOG_INTVAL 30

#define VERSION "Protocol Transfer Gateway 2.0.1"

struct itimerval timer;

pthread_t dec_rx_thread;
pthread_t enc_rx_thread;
pthread_t enc_th_thread;
pthread_t dec_th_thread;

/* FEC処理ループ関数 */
void encode_func_char(session_t *sp);
void decode_func_char(session_t *sp);

/* 受信ループ関数 */
void *DEC_RX_Loop_Thread(session_t *sp);
void *ENC_RX_Loop_Thread(session_t *sp);
/* スルーループ関数 */
void *ENC_TH_Loop_Thread(session_t *sp);
void *DEC_TH_Loop_Thread(session_t *sp);

/* Associative array for storing settings during loading */
static asarray *aa;

struct {
    int symsize;
    int genpoly;
    int fcs;
    int prim;
    int nroots;
    int ntrials;
} Tab[] = {
    {2, 0x7,     1,   1, 1, 10 },
    {3, 0xb,     1,   1, 2, 10 },
    {4, 0x13,    1,   1, 2, 10 },
    {5, 0x25,    1,   1, 6, 10 },
    {6, 0x43,    1,   1, 8, 10 },
    {7, 0x89,    1,   1, 10, 10 },
    {8, 0x11d,   1,   1, 16, 10 },
    {8, 0x187,   112,11, 32, 10 }, /* Duplicates CCSDS codec */
    {9, 0x211,   1,   1, 32, 10 },
    {10,0x409,   1,   1, 32, 10 },
    {11,0x805,   1,   1, 32, 10 },
    {12,0x1053,  1,   1, 32, 5 },
    {13,0x201b,  1,   1, 32, 2 },
    {14,0x4443,  1,   1, 32, 1 },
    {15,0x8003,  1,   1, 32, 1 },
    {16,0x1100b, 1,   1, 32, 1 },
    {0, 0, 0, 0, 0, 0},
};

int sym = 2; /* defaut is 2(4) */

typedef struct {
    int e_flag; /* encode flag */
    int d_flag; /* decode flag */
//    int n_flag; /* no fec flag */
    int f_flag; /* read from file */
    int l_flag; /* log file */
} flags_t;

void
session_init(session_t *sp){
    memset(sp, 0, sizeof(session_t));
    sp->session_num = 1;
    sp->relay_num = 0;
    sp->b_size = 15;
    sp->through = 0;
    sp->hostip = 0;
    sp->netmask = 0;
    sp->network = 0;
    sp->destnet = 0;
    sp->destmask = 0;
    sp->lossrate = 0;
//    sp->mac = 0;
//    sp->localnet = NULL;
//    sp->hostip6 = NULL;
    sp->enable_ipv6 = 0;
    sp->prefix = 0;
    sp->d_port_cnt = 0;
    sp->DServAddr.port = SERV_PORT;
}

static void usage()
{
    printf("## %s ##\n",VERSION);
    printf("Usage:\n"); 
    printf("\t./ptgate -e 192.168.1.10 -d\n");
    printf("\tEncapsulation : -e encoder_dest_addr\n");
    printf("\tDecapsulation : -d \n");
    printf("Options:\n");
    printf("  -e\tEncapsulation option\n");
    printf("  -d\tDecapsulation option\n");
    printf("  -E\tSet send port number\n");
    printf("  -D\tSet recv port number\n");
    printf("  -t\tThrough mode (Not using FEC)\n");
    printf("  -j\tDecapsulation and Forwarding\n");
    printf("  -J\tSet forwarding port\n");
    printf("  -r\tSet redudancy\t[redudancy (1 to 7)](default 4)\n");
    printf("  -R\tSet code symbol size\t[4 or 5]\n");
    printf("  -f\tRead config file\n");
    printf("  -l\tFor logging\n");
    printf("  -Z\tGenerate packet losses (%) (For Debug)\n");
    printf("  -h\tShow help\n");

    exit (-1);
}

static set_d_port(session_t *sp, char *tp){
    tp = strtok(NULL,"@");
    if(tp != NULL){
        if(sp->d_port_cnt < MAX_DPORTS)
        {
            sp->d_port[sp->d_port_cnt] = (int)atoi(tp);
            sp->d_port_cnt++;
        } else {
            printf("Please input less than 5 ports\n");
            usage();
            exit(1);
        }
        set_d_port(sp, tp);
    }
}

static set_multi_enc(session_t *sp, char *tp){

    tp = strtok(NULL,"@");

    if(tp != NULL){
        if(sp->session_num - 1 < MAX_CLIENTS)
        {
            sp->ESendAddr[sp->session_num].addr = tp;
            sp->session_num++;
        } else {
            printf("Please input less than 5 hosts\n");
            usage();
            exit(1);
        }
        set_multi_enc(sp, tp);
    }
}

static set_multi_host(session_t *sp, char *tp){

    tp = strtok(NULL,"@");

    if(tp != NULL){
        if(sp->relay_num < MAX_CLIENTS)
        {
            sp->RSendAddr[sp->relay_num].addr = tp;
            sp->relay_num++;
        } else {
            printf("Please input less than 5 hosts\n");
            usage();
            exit(1);
        }
        set_multi_host(sp, tp);
    }
}

static void hex2inet(int addr){
    printf("%d", (addr&0xff000000) >> 24);
    printf(".%d",(addr&0x00ff0000) >> 16);
    printf(".%d",(addr&0xff00) >> 8);
    printf(".%d\n",(addr&0x00ff));
}

static void print_status(session_t *sp){

    int mask, netaddr;

    printf("LOCAL Parameters:\n");
    getifhwaddr(INTERFACE, sp->mac);
    printf("\tMAC Address     : %02X:%02X:%02X:%02X:%02X:%02X\n",
	        sp->mac[0], sp->mac[1], sp->mac[2],
            sp->mac[3], sp->mac[4], sp->mac[5]);
    
    sp->hostip = getifhexaddr(INTERFACE);
//    printf("IPv4 addr: 0x%x\n",sp->hostip);
    printf("\tIPv4 Address    : ",sp->hostip);

    hex2inet(sp->hostip);

    mask = getifmask(INTERFACE);
    sp->netmask = mask;
    printf("\tNetmask         : ", sp->netmask);
    hex2inet(sp->netmask);

    netaddr = ntohl(sp->hostip&sp->netmask);
    sp->network = netaddr;
    printf("\tNetwork Address : ",ntohl(netaddr));
    hex2inet(ntohl(netaddr));

    if(getv6addr(sp) != -1){
        sp->enable_ipv6 = 1;
        printf("\tIPv6 Address    : %s/%d\n",sp->hostip6,sp->prefix);
    }

}

static void print_settings(session_t *sp, flags_t *flags){

    int i;

    printf("Setting Parameters:\n");

    printf("\tEncapsulation Mode  : ");
    if(flags->e_flag){
        printf("[ ON ]\n");
        printf("\t   FEC Redundancy   : ");
        if(sp->through == 0){
        printf("Reed-Solomon (%d,%d) code\n", 
                (2 << (sym + 1)) - 1, (2 << (sym + 1)) - 1 - Tab[sym].nroots);
        } else {
            printf(" none\n");
        }

        if(sp->session_num == 1){
            printf("\t   Destination Host : ");
        } else if(sp->session_num > 1){
            printf("\t   Destination Hosts: ");
        }

        for(i = 0; i < sp->session_num; i++){
            printf("%s  ",sp->ESendAddr[i].addr);
            if(i == (sp->session_num - 1)){
                printf("\n");
            }
        }
        if(sp->destnet){
            printf("\t   Destination Network : ");
            hex2inet(ntohl(sp->destnet));
        }

        if(sp->d_port_cnt != 0){
            printf("\t   Unacceptable Port : ");
        }

        for(i = 0; i < sp->d_port_cnt; i++){
            printf("%d ",sp->d_port[i]);
            if(i == (sp->d_port_cnt - 1)){
                printf("\n");
            }
        }
    } else {
        printf("[ OFF ]\n");
    }

    printf("\tDecapsulation Mode  : ");
    if(flags->d_flag){
        printf("[ ON ]\n");
    } else {
        printf("[ OFF ]\n");
    }

    printf("\tRelay Mode          : ");
    if(sp->relay_num){
        printf("[ ON ]\n");
    } else {
        printf("[ OFF ]\n");
    }

    if(sp->relay_num == 1){
        printf("\t   Relay Host       : ");
    } else if(sp->relay_num > 1){
        printf("\t   Relay Hosts      : ");
    }

    for(i = 0; i < sp->relay_num; i++){
        printf("%s  ",sp->RSendAddr[i].addr);
        if(i == (sp->relay_num - 1)){
            printf("\n");
        }
    }

    printf("\tOutput Logfile      : ");
    if(l_st->log_file != NULL){
        printf("[ ON ]\n");
    } else {
        printf("[ OFF ]\n");
    }
}



/* SIGINTを受け取ったら終了処理 */
static void intr_handler(int n)
{
//  int s0;
//  struct ifreq if_req;
  /* スレッド後処理 */
#if 0
    pthread_cancel(dec_rx_thread);
    pthread_join(dec_rx_thread,NULL);
    pthread_cancel(enc_rx_thread);
    pthread_join(enc_rx_thread,NULL);
    pthread_cancel(enc_th_thread);
    pthread_join(enc_th_thread,NULL);
    pthread_cancel(dec_th_thread);
    pthread_join(dec_th_thread,NULL);
#endif
#if 0
  pthread_cancel(enc_thread);
  pthread_join(enc_thread,NULL);
  pthread_cancel(dec_thread);
  pthread_join(dec_thread,NULL);
#endif

    recover_from_promisc(INTERFACE);
    syslog(LOG_INFO, "Stop : %s", VERSION);

    exit(0);
}

static int
version_string(char *buf)
{
    strcpy (buf, VERSION);
    return 0;
}

static int
print_version(void)
{
    char buf[80];

    version_string(buf);
    printf("## %s ##\n", buf);

    return 0;
}

static int
setting_load(const char *key, char **value)
{
    return asarray_lookup(aa, key, value);
}

static int
setting_load_int(const char *name, int default_value)
{
    char *value;

    if(setting_load(name, &value)){
        return atoi(value);
    }

    return default_value;
}

static char *
setting_load_str(const char *name, char *default_value)
{
    char *value;

    if(setting_load(name, &value)){
        return value;
    }

    return default_value;
}

static void load_enc_point(session_t *sp, char *esend, char *esend_port, int i){

    if(setting_load_str(esend, NULL) != NULL){
        sp->ESendAddr[i].addr = setting_load_str(esend, NULL);
        sp->ESendAddr[i].port = setting_load_str(esend_port, "9004");
        sp->session_num++;
    }
}

static void load_relay_point(session_t *sp, char *rsend, char *rsend_port, int i){

    if(setting_load_str(rsend, NULL) != NULL){
        sp->RSendAddr[i].addr = setting_load_str(rsend, NULL);
        sp->RSendAddr[i].port = setting_load_str(rsend_port, "9004");
        sp->relay_num++;
    }
}

static void load_denial_port(session_t *sp, char *dport, int i){

    if((setting_load_int(dport, 0)) != 0){
        sp->d_port[i] = setting_load_int(dport, 0);
        sp->d_port_cnt++;
    }
}

static void load_config(session_t *sp, flags_t *flags, char *destnet){

    int i;
    char esend[6][10] = {"Dst_host1","Dst_host2","Dst_host3","Dst_host4","Dst_host5"};
    char esend_port[6][15] = {"Dst_host1_port","Dst_host2_port","Dst_host3_port",
                              "Dst_host4_port","Dst_host5_port"};
    char rsend[6][10] = {"Rly_host1","Rly_host2","Rly_host3","Rly_host4","Rly_host5"};
    char rsend_port[6][15] = {"Rly_host1_port","Rly_host2_port","Rly_host3_port",
                              "Rly_host4_port","Rly_host5_port"};
    char dport[6][15] = {"Dport","Dport2","Dport3", "Dport4","Dport5"};

    /* THROUGH PARAM */
    if(setting_load_int("Through", 0)){
        sp->through = 1;
    }

    /* ENCAP PARAM */
    if(setting_load_int("Encapsulation", 0)){
        flags->e_flag = 1;
        
        if(setting_load_str(esend[0], NULL) != NULL){
            sp->ESendAddr[0].addr = setting_load_str(esend[0], NULL);
            sp->ESendAddr[0].port = setting_load_str(esend_port[0], "9004");
        }

        for(i = 1; i < 5; i++){
            load_enc_point(sp, esend[i], esend_port[i], i);
        }

        if(setting_load_str("destnet", NULL) != NULL){
            destnet = setting_load_str("destnet", NULL);
            sp->destmask = setting_load_int("destmask", 24);
            sp->destnet = (inet_addr(destnet));
        }
        if(setting_load_int("Redundancy", 0)){
            Tab[sym].nroots = setting_load_int("Redundancy", 2);
        }

        if(setting_load_str("M_srcaddr", NULL) != NULL){
            strcpy(sp->m_taddr6 ,setting_load_str("M_srcaddr", NULL));
        }
    }

    /* DECAP PARAM */
    if(setting_load_int("Decapsulation", 0)){
        flags->d_flag = 1;
        sp->DServAddr.port = setting_load_str("Drecv_port", "9004");

        if(setting_load_str("Dmrecv", NULL) != NULL){
            sp->serv_group_d = setting_load_str("Dmrecv", NULL);
        }
    }

    /* RELAY PARAM */
    if(setting_load_int("Relay", 0)){
        for(i = 0; i < 5; i++){
            load_relay_point(sp, rsend[i], rsend_port[i], i);
        }
    }

    /* DPORT PARAM */
    for(i = 0; i < 5; i++){
        load_denial_port(sp , dport[i], i);
    }

    /* PRINT LOG */
    if(setting_load_int("Logfile", 0)){
        flags->l_flag = 1;
    }
}

static int
read_config(char *filename){
    FILE *conf_file;
    char buffer[256];
    char *key, *value;

    asarray_create(&aa);

    if((conf_file = fopen(filename, "r")) == NULL){
        printf("Can not open config file!\n");
        exit(1);
    }

    while(fgets(buffer, 256, conf_file) != NULL){
        if(buffer[0] != '*') {
//            printf("Garbage ignored: %s\n", buffer);
            continue;
        }

        key = (char *)strtok(buffer,":");
        if(key == NULL){
            continue;
        }
        /* skip asterisk */
        key = key + 1;
        value = (char *) strtok(NULL, "\n");

        if(value == NULL){
            continue;
        }

        while(*value != '\0' && isascii((int)*value) && isspace((int)*value)){
            /* skip leading spaces, and stop skipping if not ascii */
            value++;
        }

        asarray_add(aa, key, value);
#if 0
                if(strcmp(key, "encode") == 0){
                        printf("Set Encode mode: ");
                         key = strtok(NULL,":");
                        args->enc = atoi(key);
                        printf("%d\n", args->enc);
                }
                if(strcmp(key, "decode") == 0){
                        printf("Set Decode mode: ");
                         key = strtok(NULL,":");
                        args->dec = atoi(key);
                        printf("%d\n", args->dec);
                }
                if(strcmp(key, "send") == 0){
                        printf("Set Send Address: ");
                         key = strtok(NULL,":");
                        args->send = key;
                        printf("%s", args->send);
                }
                if(strcmp(key, "recv") == 0){
                        printf("Set Recv Address: ");
                         key = strtok(NULL,":");
                        args->recv = key;
                        printf("%s", args->recv);
                }
#endif
        }
        fclose(conf_file);
    return 1;
}

/* 時間取得関数 */
static void get_time(char *timep, int flags){
    time_t  t;

    time(&t);
    strcpy(timep, ctime(&t));

    if(flags){
        /* 時間だけ抽出 */
        timep[strlen(ctime(&t)) - 6] = '\0';
        strcpy(timep, timep + 11);
    } else {
        /* \nの除去 */
        timep[strlen(ctime(&t)) - 1] = '\0';
    }
}

/* 通信ログ表示 */
static void show_logs(FILE *fp, int cnt, int start){

    char    timep[30];
    int enc_recv, dec_recv;

    if(start == 0){
        get_time(timep, 0);
        fprintf(fp,"# %s \n", timep);
        fprintf(fp,"# START Reed Solomon (%d,%d) code\n", 
                (2 << (sym + 1)) - 1, (2 << (sym + 1)) - 1 - Tab[sym].nroots);
    }

    enc_recv = l_st->enc_ring_pkt;
    if(enc_recv < 0){
            enc_recv += MAX_RECVBUF_NUM;
    }

    dec_recv = l_st->dec_ring_pkt;
    if(dec_recv < 0){
            dec_recv += MAX_RECVBUF_NUM;
    }

    get_time(timep, 1);

    if(cnt == 0){
        fprintf(fp,
            "#              (Encap)             |            (Decap)           \n");
        fprintf(fp,
            "#[ time  ]  RX_pkt   TX_pkt    RX_Q |   RX_pkt     Loss_pkt   TX_pkt   RX_Q | TH  LR  RY\n");
        fprintf(fp,
            "#---------+------+-----------+------+------------+-----------+-------+------+-------------\n");
    } 
        fprintf(fp,
//            "[%s]  %4d  (%4d,%4d) %4d  | (%4d,%4d)  %3d (%3d)    %4d  %4d %4d %4d\nenc_avg %d [us] dec_avg %d[us]\n", 
            "[%s]  %4d  (%4d,%4d) %4d  | (%4d,%4d)  %3d (%3d)    %4d  %4d  |%3d %3d %3d\n", 
            timep, l_st->enc_recv_pkt, l_st->enc_send_pkt, l_st->enc_fec_pkt, 
            enc_recv, l_st->dec_recv_pkt, l_st->dec_fec_pkt, 
            l_st->loss_pkt - l_st->recover_pkt, l_st->loss_pkt, 
//            l_st->dec_send_pkt, dec_recv, l_st->allow, l_st->deny, l_st->enc_avg_time, l_st->dec_avg_time);
            l_st->dec_send_pkt, dec_recv, l_st->allow, l_st->deny, l_st->relay_pkt);
            fflush(l_st->log_file);

}

static void clear_logs(){
    l_st->loss_pkt = 0;
    l_st->recover_pkt = 0;

    l_st->dec_recv_pkt = 0;
    l_st->dec_send_pkt = 0;
    l_st->dec_fec_pkt = 0;

    l_st->enc_recv_pkt = 0;
    l_st->enc_send_pkt = 0;
    l_st->enc_fec_pkt = 0;
    l_st->allow = 0;
    l_st->deny = 0;
    l_st->relay_pkt = 0;
}

static void
record_stat(int sig)
{
    static int  cnt = 0;
    static int  start = 0;

    /* 標準出力へ */
    show_logs(stdout, cnt, start);

    /* ファイルへ書き出し */
    if(l_st->log_file != NULL){
        show_logs(l_st->log_file, cnt, start);
    }

    cnt++;
    cnt = cnt % LOG_INTVAL;
    start = 1;

    /* パラメータを定期的に消去 */
    clear_logs();
}

static void setting_timer(void){
    signal(SIGALRM, record_stat);
    timer.it_interval.tv_sec = TIMEOUT_SEC;
    timer.it_interval.tv_usec = TIMEOUT_USEC;
    timer.it_value.tv_sec = TIMEOUT_SEC;
    timer.it_value.tv_usec = TIMEOUT_USEC;
    setitimer(ITIMER_REAL, &timer, NULL);    
}

static int
wakeup_procs(session_t *sp, flags_t *flags){

    pid_t pid;

    /* call encode_func */    
    if(flags->e_flag && !(flags->d_flag))
    {  
        if(pthread_create(&enc_rx_thread, NULL, (void *)ENC_RX_Loop_Thread, (void *)sp) != 0)
        {
            perror("cteate encode thread failed");
            exit(0);
        }

        if(pthread_create(&enc_th_thread, NULL, (void *)ENC_TH_Loop_Thread, (void *)sp) != 0)
        {
            perror("cteate encode thread failed");
            exit(0);
        }

        encode_func_char(sp);
    }

    /* call decode_func */
    if(flags->d_flag && !flags->e_flag)
    {  
        {
            if(pthread_create(&dec_rx_thread, NULL, (void *)DEC_RX_Loop_Thread, (void *)sp) != 0)
            {
                perror("create decode thread failed");
                exit(0);
            }
            if(pthread_create(&dec_th_thread, NULL, (void *)DEC_TH_Loop_Thread, (void *)sp) != 0)
            {
                perror("create decode thread failed");
                exit(0);
            }

            decode_func_char(sp);    
        }
    }

    if(flags->e_flag && flags->d_flag)
    {
        switch(pid=fork())
        {
            case 0:
                if(pthread_create(&enc_rx_thread, NULL, (void *)ENC_RX_Loop_Thread, (void *)sp) != 0) {
                    perror("pthread create failed");
                    exit(0);
                }
                if(pthread_create(&enc_th_thread, NULL, (void *)ENC_TH_Loop_Thread, (void *)sp) != 0) {
                    perror("pthread create failed");
                    exit(0);
                }
                encode_func_char(sp);
        case -1:
            perror("pthread4() failed");    
        break;

        case 1:
        break;
    }
   
    switch(pid=fork())
    {
        case 0:

        {
            if(pthread_create(&dec_rx_thread, NULL, (void *)DEC_RX_Loop_Thread, (void *)sp) != 0)
            {
                perror("pthread create failed");
                exit(0);
            }
            if(pthread_create(&dec_th_thread, NULL, (void *)DEC_TH_Loop_Thread, (void *)sp) != 0)
            {
                perror("pthread create failed");
                exit(0);
            }
            decode_func_char(sp);    
    }

        case -1:
            perror("pthread4() failed");    
        break;

        case 1:
        break;
    }
    pid=wait(0);
    pid=wait(0);
 }
 return 0;   
}

static void setprio(void){
    int prio;

    if(geteuid() != 0){
        fprintf(stderr,"#\n# This program requires superuser privilege.\n# You must have \"root\" privilege to execute this program.\n#\n");
        exit(0);
    }

    setpriority(PRIO_PROCESS, 0, -20);
    prio = getpriority(PRIO_PROCESS, 0);
    printf("#  setting priority : %d\n",prio);
}

int
main(int argc, char *argv[])
{
//    char *ESendIP[MAX_CLIENTS];
    char* ESendPort = SEND_PORT;
//    char* DServPort = SERV_PORT;
//    char *RSendIP[MAX_CLIENTS];
    char* RSendPort = SEND_PORT;
    char *tp = NULL;
    int i, sw, id;
//    char    *serv_group_dec = NULL;
    char *adr;
    session_t *sp;
    flags_t *flags;
//    char *ipaddr;
//    char hostip[20];
//    char *lnet;
//    int mask, netaddr;
    char *destnet;

    th_args_t *enc_th_args;
    th_args_t *dec_th_args;

    pid_t p_pid;

#if TH
    dec_recv_buf = (ringbuf_t *)malloc(sizeof(ringbuf_t));
    memset(dec_recv_buf, 0, sizeof(ringbuf_t));
    enc_recv_buf = (ringbuf_t *)malloc(sizeof(ringbuf_t));
    memset(enc_recv_buf, 0, sizeof(ringbuf_t));
    enc_th_buf = (ringbuf_t *)malloc(sizeof(ringbuf_t));
    memset(enc_th_buf, 0, sizeof(ringbuf_t));
    dec_th_buf = (ringbuf_t *)malloc(sizeof(ringbuf_t));
    memset(dec_th_buf, 0, sizeof(ringbuf_t));
#endif

    sp = (session_t *)malloc(sizeof(session_t));
    session_init(sp);

    /* log status create */
    if((id = shmget(IPC_PRIVATE, sizeof(log_stat), IPC_CREAT|0666)) < 0){
            perror("shmget");
            exit(-1);
    }
//    printf("shared memory ID = %d\n", id);

    if((adr = shmat(id, 0, 0)) < 0){
            perror("shmat");
    }

    memset(adr, 0, sizeof(log_stat));
    l_st = (log_stat *)adr;

    flags = (flags_t *)malloc(sizeof(flags_t));
    memset(flags, 0, sizeof(flags_t));

    p_pid = getpid();
  
    while((sw = getopt(argc, argv, "e:dr:R:b:D:tlf:E:n:g:Z:j:J:i:g:G:p:")) !=EOF)
    {
      switch(sw)
    {
    case 'e':
      /* encode option*/ 
      flags->e_flag = 1;
      tp = strtok(optarg,"@");
//      ESendIP[sp->session_num - 1] = tp;
      sp->ESendAddr[sp->session_num - 1].addr = tp;
      if(tp != NULL){

          set_multi_enc(sp, tp);
#if 0
        tp = strtok(NULL,"@");
        if(tp != NULL){
            sp->session_num++;
//            ESendIP[sp->session_num - 1] = tp;
            sp->ESendAddr[sp->session_num - 1 ].addr = tp;

        	tp = strtok(NULL,"@");
      		if(tp != NULL){
                sp->session_num++;
//                ESendIP[sp->session_num - 1] = tp;
                sp->ESendAddr[sp->session_num - 1 ].addr = tp;

                tp = strtok(NULL,"@");
                if(tp != NULL){
                    printf("Please input less than 3 hosts\n");
                    usage();
                    exit(1);
                }
            }
        } 
#endif
     } 
      break;
    case 'E':
      ESendPort = optarg;
      break; 
    case 'n':
      /* network option*/ 
      tp = strtok(optarg,"/");
      destnet = tp;
      sp->destnet = inet_addr(destnet);
      if(tp != NULL){
          tp = strtok(NULL,"/");
        if(tp != NULL){
              sp->destmask = atoi(tp);
        } else {
              sp->destmask = 24;
        }
      } 
      break;
   case 'd':
      /* decode option*/ 
      flags->d_flag=1;
      break;
   case 'D':
//      DServPort = optarg;
      sp->DServAddr.port = optarg;
      break;
   case 't':
      /* through option*/
      sp->through = 1;
      break;
    case 'j':
      /* relay option*/ 
      tp = strtok(optarg,"@");
//      RSendIP[sp->relay_num] = tp;
      sp->RSendAddr[sp->relay_num].addr = tp;
      sp->relay_num++;
      if(tp != NULL){
#if 0
        tp = strtok(NULL,"@");
        if(tp != NULL){
            RSendIP[sp->relay_num] = tp;
            sp->relay_num++;

        	tp = strtok(NULL,"@");
      		if(tp != NULL){
                RSendIP[sp->relay_num] = tp;
                sp->relay_num++;
                tp = strtok(NULL,"@");
                if(tp != NULL){
                    printf("Please input less than 3 hosts\n");
                    usage();
                    exit(1);
                }
            }
        } 
#endif
     set_multi_host(sp, tp);
     } 
   break;
   case 'J':
      RSendPort = optarg;
      break;
   case 'r':
      /* redudance option*/
         Tab[sym].nroots = (int)atoi(optarg);
      break;
    case 'R':
      sym = (int)atoi(optarg) - 2;
      if(sym == 2){
        sp->b_size = 15;
      }else if(sym == 6){
        sp->b_size = 255;
      }
      break;
    case 'b':
      sp->b_size = (int)atoi(optarg);
      break;
    case 'f':
      flags->f_flag = 1;
      read_config(optarg);
      break; 
    case 'M':
      sp->serv_group_d = optarg;
      break;
    case 'i':
      break;
    case 'g':
      strcpy(sp->m_taddr, optarg);
      break;
    case 'G':
      strcpy(sp->m_taddr6, optarg);
      break;
    case 'p':
      tp = strtok(optarg,"@");
      sp->d_port[sp->d_port_cnt] = (int)atoi(tp);
      sp->d_port_cnt++;
      set_d_port(sp, tp);
     break;
    case 'l':
      flags->l_flag = 1;
/*      if((l_st->log_file = fopen(LOGFILE, "a+w")) == NULL){
          printf("Can not open output file!\n");
          exit(1);
      }
      */
      break; 
    case 'Z':
      sp->lossrate = (double)atoi(optarg);
      break; 
    case 'h':
    default:
      usage();
      break; 
    }
    }

//    argc -= optind;
//    argv += optind;

    print_version();

    syslog(LOG_INFO, "Start : %s", VERSION);

    signal(SIGINT, intr_handler);

    setprio();

#if 0
    struct addrinfo *ai;
    ai = host_serv(ESendIP[0], NULL ,0, 0);
#endif
    
    print_status(sp);

#if 0
    getifhwaddr(INTERFACE, sp->mac);
    printf("MAC addr : %02x:%02x:%02x:%02x:%02x:%02x\n",
	sp->mac[0], sp->mac[1], sp->mac[2], sp->mac[3], sp->mac[4], sp->mac[5]);
//    ipaddr = getifaddr(INTERFACE);
    sp->hostip = getifhexaddr(INTERFACE);
//    sprintf(hostip, "%s", ipaddr);
//    sp->hostip = ipaddr;
//    sp->hostip = hostip;

    mask = getifmask(INTERFACE);
//    printf("My Host Netmask: 0x%x\n", mask);
    sp->netmask = mask;
    printf("IPv4 addr: 0x%x\n",sp->hostip);
    printf("Netmask  : 0x%x\n", sp->netmask);
    netaddr = ntohl(sp->hostip&sp->netmask);
    sp->network = netaddr;
    printf("Network  : 0x%x\n",ntohl(netaddr));
    if(getv6addr(sp) != -1){
        sp->enable_ipv6 = 1;
        printf("IPv6 addr: %s/%d\n",sp->hostip6,sp->prefix);
    }

//    sprintf(localnet,"%s",inet_ntoa_ex(ntohl(netaddr)));
//    printf("Netmask: %s\n",localnet);
//    printf("My Host Netmask: %s\n", inet_ntoa_ex(ntohl(netaddr)));
//    sp->localnet = inet_ntoa_ex(netaddr);
//    sprintf(lnet,"%s",inet_ntoa_ex(netaddr));
//    printf("Netmask: %s\n",sp->localnet);
//    sp->localnet = localnet;
//    printf("Netmask: %s\n",sp->localnet);
//    sp->localnet = LOCAL_NET;
#endif

    if(argc < 2){
        usage();
    }

/*
    if(!getifrun(INTERFACE)){
        fprintf(stderr, "\n# Please check your ethernet port!\n");
        exit(0);
    }
*/

    /* set sig_alarm */
    setting_timer();

    if(flags->f_flag){
        load_config(sp, flags, destnet);
#if 0
        if(setting_load_int("encode", 0)){
            flags->e_flag = 1;
            sp->ESendAddr[0].addr = setting_load_str("esend", NULL);
            ESendPort = setting_load_str("esend_port", "9004");

            if(setting_load_str("esend2", NULL) != NULL){
                  sp->ESendAddr[1].addr = setting_load_str("esend2", NULL);
                  sp->session_num++;
            }

            if(setting_load_str("esend3", NULL) != NULL){
                  sp->ESendAddr[2].addr = setting_load_str("esend3", NULL);
                  sp->session_num++;
            }
        }

        if(setting_load_str("destnet", NULL) != NULL){
            destnet = setting_load_str("destnet", NULL);
            sp->destmask = setting_load_int("destmask", 24);
            sp->destnet = (inet_addr(destnet));
        }

        if(setting_load_int("decode", 0)){
            flags->d_flag = 1;
            DServPort = setting_load_str("recv_port", "9004");

            if(setting_load_str("dmrecv", NULL) != NULL){
                  serv_group_dec = setting_load_str("dmrecv", NULL);
            }
        }
#endif
    } 

    /* set encode related value */
    if(flags->e_flag){
//        if(!ESendIP[0]){
        if(!sp->ESendAddr[0].addr){
            perror("Please Enter Send IP Addr");
            exit(0);
        }

#if 0
        if(!sp->destnet){
            /* マルチキャストのみで使用する場合はいらない */
            perror("Please Enter Destination Network Addr");
            exit(0);
        }
#endif

        if(!flags->f_flag){
            for(i = 0;i < sp->session_num; i++){
                sp->ESendAddr[i].port = ESendPort;
            }
        }
    }

    /* set decode related value */
    if(flags->d_flag){
        /* set decode rtp_server_value */ 
//        sp->DServAddr.port = DServPort;
        /* 中継する場合にIPアドレスをセット */
        for(i = 0;i < sp->relay_num; i++){
//            sp->RSendAddr[i].addr = RSendIP[i];
            sp->RSendAddr[i].port = RSendPort;
        }
   }

    if(flags->l_flag){
        if((l_st->log_file = fopen(LOGFILE, "a+w")) == NULL){
        printf("Can not open output file!\n");
        exit(1);
        }
    }

    print_settings(sp, flags);

#if 0
    if(sp->destnet){
//        printf("Destination Network : 0x%x/%d\n", ntohl(sp->destnet), sp->destmask);
        printf("Destination Network : ");
        hex2inet(ntohl(sp->destnet));
    }
#endif

 /* set Reed-Solomon value */
    if((sp->rs_handle = init_rs_char(Tab[sym].symsize, Tab[sym].genpoly, Tab[sym].fcs, Tab[sym].prim, Tab[sym].nroots, 0)) == NULL)
    {
        printf("init_rs_char failed!\n");
    }

    /* wake up main processes */
    wakeup_procs(sp, flags);

    return TRUE;
}
