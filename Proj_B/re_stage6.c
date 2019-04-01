#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/timerfd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "common.h"
#include "tun.h"
#pragma pack(1)
struct packet {
  uint32_t type;
  char data[0];
};
struct hello_pkg{
    uint32_t pid;
    uint32_t id;
    struct sockaddr_in r_addr_in;
};

struct octane_control {
    uint8_t octane_action;
    uint8_t octane_flags;
    uint16_t octane_seqno;
    uint32_t octane_source_ip;
    uint32_t octane_dest_ip;
    uint16_t octane_source_port;
    uint16_t octane_dest_port;
    uint16_t octane_protocol;
    uint16_t octane_port;
};
struct timer {
    struct timespec ts;
    int t_sockfd;
    int t_resend;
    void* t_packet;
    long t_len;
    struct sockaddr_in t_addr_in;
    struct timer *prev;
    struct timer *next;
};
struct pseudoheader {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};
#pragma pack()
struct f_entry {
    uint32_t f_src;
    uint32_t f_dst;
    uint16_t f_dport;
    uint16_t f_sport;
    uint16_t f_proto;
    uint16_t f_port;
    uint8_t f_action;
};
/*----------------------------------------*/
#define PKG_HDRLEN (sizeof(struct packet))
#define MAX_RESEND_NUM 10
#define MAX_ROUTERS 10
#define MAX_F_ENTRY 150

#define FLOW_ACT_NOTUSED     0
#define FLOW_ACT_FORWARD    1
#define FLOW_ACT_REPLY      2
#define FLOW_ACT_DROP       3
#define FLOW_ACT_REMOVE     4
/* -------------------- Global Variables -------------------- */
#define type_HELLO 0
#define type_PACKET 1
#define type_CONTROL 2
#define type_CLOSE  255

sigset_t signal_set;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t prim_thread, ctrlc_thread;
int stage;

pid_t router_pid;
int num_routers;
char buffer[BUF_SIZE];
char r_ipstore[10][40];

FILE *logfd;
int tunfd;
int sockfd, timerfd,tcpfd;
int sockaddr_size = sizeof(struct sockaddr);
socklen_t sockaddr_in_size = sizeof(struct sockaddr_in);

struct sockaddr_in addr,prim_addr_in, secd_addr_in;
struct sockaddr_in eth[10];
char iphdr_store[32];
int id;
int raw_sock;
struct in_addr orig_addr;
/*----------------------------------------*/

struct f_entry f_table[MAX_F_ENTRY];
struct timer *timer_list;
struct hello_pkg r_info[10];
int drop_after;

static char FPATH[P_MAX_LEN];

/**************************************************************************
    Parse Configuration File
**************************************************************************/
int ConfigParser(const char *path)
{
    FILE *fp = fopen(path,"r");
    char line[1000];
    //char delim = ' ';
    
    if(fp==NULL)
    {
        printf("can not load file!");
        return 1;
    }
    while(fgets(line,1000,fp)!= NULL)
    {
           if(line[0]!='#')
           {
              char *p1, *p2;
              p1 = strtok(line," ");
              p2 = strtok(NULL," ");
              if (strcmp(p1,"stage") ==0)
                  stage = atoi(p2);
              else if (strcmp(p1 , "num_routers")==0)
                  num_routers = atoi(p2);
              else if(strcmp(p1, "drop_after")==0)
                  drop_after = atoi(p2);
           }    
    }
    printf("stage: %d\tnum_routers: %d\tdrop_after: %d\n", stage, num_routers, drop_after);

    return EXIT_SUCCESS;
}

int udp_dynalloc(struct sockaddr_in *addr)
{
    int sockfd = socket(PF_INET, SOCK_DGRAM, 0);

    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr("127.0.0.1");
    addr->sin_port = htons(0);  /* assign 1024~5000 randomly */
    bind(sockfd, (struct sockaddr*) addr, sockaddr_in_size);
    getsockname(sockfd, (struct sockaddr*) addr, &sockaddr_in_size);
    return sockfd;
}

void LOG(FILE *fp, const char *format,...)
{
    if(fp == NULL) return;
    va_list args;
    va_start(args, format);
    vfprintf(fp, format, args);
    va_end(args);
    fflush(fp);
}
// From RFC 1071
unsigned short checksum(char *addr, short count)
{
       /* Compute Internet Checksum for "count" bytes
        *         beginning at location "addr".
        */
       register long sum = 0;

        while( count > 1 )  {
           /*  This is the inner loop */
               sum += *(unsigned short *) addr;
         addr += 2;
               count -= 2;
       }

           /*  Add left-over byte, if any */
       if( count > 0 )
               sum += * (unsigned char *) addr;

           /*  Fold 40-bit sum to 16 bits */
       while (sum>>16)
           sum = (sum & 0xffff) + (sum >> 16);

       return (unsigned short) ~sum;
}
unsigned short tcp_checksum(void *p, int len) {
    struct ip *ip=(struct ip *)p;
    struct tcphdr *tcp=(struct tcphdr *)(ip+1);
    uint16_t total_len = 0;
    unsigned short ret;

    char *b = malloc(len+sizeof(struct pseudoheader));
    if(b == NULL) return 0;

    struct pseudoheader hdr;
    hdr.src = ip->ip_src.s_addr;
    hdr.dst = ip->ip_dst.s_addr;
    hdr.zero = 0;
    hdr.proto = 6;
    hdr.len = htons(len - 20); /*tcp lenghth = len - iphdr*/
    
    memcpy(b, &hdr, sizeof(struct pseudoheader));
    total_len = sizeof(struct pseudoheader);
    tcp->th_sum = 0;
    memcpy(b+total_len, tcp, len - 20);
    total_len += len - 20;
    ret = checksum(b, total_len);
    free(b);

    return ret;
}
void CommandLineParser(int argc, const char *argv[])
{
    if (argc <= 1)
    {
        fprintf(stderr, "lack of args!\n");
        fprintf(stderr, "usage: %s %s\n", "proja", "[tfile]");
        exit(1);
    }
    else if (argc ==2)
    {
        /* argv[1] filepath */
        strcpy(FPATH, argv[1]);
        if (access(FPATH,F_OK)!=0) {
            fprintf(stderr, "File doesn't exist");
            exit(1);
        }
    }
    else
    {
        fprintf(stderr, "Too many args!\n");
        fprintf(stderr, "input format: %s %s\n", "proja", "[tfile]");
        exit(1);
    }
}

int raw_icmp_alloc(){
    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    printf("id is %d, raw_sock is %d\n", id, raw_sock);
    if ((bind(raw_sock, (struct sockaddr*) &eth[id], sizeof(eth[id])))<0){
        perror("raw_icmp_alloc bind error");
        exit(-1);
    }
    tcpfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if ((bind(tcpfd, (struct sockaddr*) &eth[id], sizeof(eth[id])))<0){
        perror("raw_icmp_alloc bind TCP error");
        exit(-1);
    }
  return raw_sock;
}
int raw_tcp_alloc(){
    tcpfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if ((bind(tcpfd, (struct sockaddr*) &eth[id], sizeof(eth[id])))<0){
        perror("raw_icmp_alloc bind TCP error");
        exit(-1);
    }
  return tcpfd;
}
void eth_allocIP()
{
    int i;
    char eth_ip[32];
    for (i = 1; i <= num_routers; i++) {
        sprintf(eth_ip, "192.168.20%d.2", i);
        memset(&eth[i], 0, sizeof(struct sockaddr_in));
        eth[i].sin_family = AF_INET;
        inet_aton(eth_ip, &eth[i].sin_addr);
        printf("IP address: %s\n", inet_ntoa(eth[i].sin_addr));
    }
}

void exchange_src_dst(struct f_entry *f) {
    uint32_t tmp_timerip = f->f_src;
    uint16_t tmp_timerport = f->f_sport;
    f->f_src = f->f_dst;
    f->f_dst = tmp_timerip;
    f->f_sport = f->f_dport;
    f->f_dport = tmp_timerport;
}

char *f_to_string(struct f_entry *f) {
    static char str[256];
    char src[40],dst[40];
    struct in_addr sc,dt;
    sc.s_addr = f->f_src;
    dt.s_addr = f->f_dst;
    strcpy(src,inet_ntoa(sc));
    strcpy(dst,inet_ntoa(dt));
    sprintf(str,"(%s, %d, %s, %d, %d) action %d", src,
            ntohs(f->f_sport), dst, ntohs(f->f_dport), f->f_proto, (f->f_action));
    return str;
}
/*--------------------------------------------------------------------------------*/
void* ctrlc_handler(void* arg){
    int sig, status;
    sigwait(&signal_set, &sig);
    pthread_mutex_lock(&mutex);
    /*---------------------Clean up----------------------*/
    printf("\nCatch ctrl+c, cleanning...\n");

    close(tunfd);
    /* kill router process */
    kill(router_pid, SIGTERM);
    wait(&status);
    /*if (WIFSIGNALED(status))//if child proc terminate because of signal
        printf("Child process received singal %d\n", WTERMSIG(status));*/
    fflush(logfd);
    close(sockfd);
    close(raw_sock);
    close(timerfd);
    fclose(logfd);
    pthread_cancel(prim_thread);
    /*--------------------------------------------------*/
    pthread_mutex_unlock(&mutex);

    return (void*)0;
}

/*--------------------------timer----------------------------------*/
int timer_search(struct timespec *t1, struct timespec *t2) {
    if(t1->tv_sec > t2->tv_sec) 
        return 1;
    if(t1->tv_sec == t2->tv_sec) {
        if(t1->tv_nsec > t2->tv_nsec)
            return 1;
    }
    return 0;
}
void time_off_list(struct timer *t) {
    if(timer_list == t) {
        timer_list = t->next;
        return;
    }
    if(t->next)
        t->next->prev = t->prev;
    if(t->prev)
        t->prev->next = t->next;
}
void timer_to_list(struct timer *t, struct timer **list_hdr) {
    struct timer *tmp_timer = *list_hdr;
    if(*list_hdr == NULL) {
        *list_hdr = t;
        t->prev = NULL;
        t->next = NULL;
        return;
    }else{
        /*find the last one*/
        while(tmp_timer->next != NULL) {
            tmp_timer = tmp_timer->next;
        }
        tmp_timer->next = t;
        t->next = NULL;
        t->prev = tmp_timer;
        struct timespec now;
        struct itimerspec itspec;
        memset(&itspec, 0, sizeof(itspec));
        clock_gettime(CLOCK_REALTIME, &now);
        t->ts = now;
        t->ts.tv_sec += 2;
        itspec.it_value = t->ts;
        timerfd_settime(timerfd, TFD_TIMER_ABSTIME, &itspec, NULL);
    }
}
void timer_add(int sockfd, void *packet, int len, struct sockaddr_in *to_addr_in) {
    struct timer *t = (struct timer*)malloc(sizeof(struct timer));
    if(t == NULL){
        printf("timer_add malloc timmer failed.\n");
        return;
    }
    void *pack = malloc(len);
    if(pack == NULL){
        printf("timer_add malloc packet failed.\n");
        return;
    }
    t->t_sockfd = sockfd;
    t->t_packet = pack;
    t->t_len = len;
    t->t_addr_in = *to_addr_in;
    t->t_resend = 0;
    memcpy(t->t_packet, packet, len);
    if(t->t_resend <= MAX_RESEND_NUM){
        t->t_resend++;
        int strLen = sendto(t->t_sockfd, t->t_packet, t->t_len, 0, (struct sockaddr*)&(t->t_addr_in), sockaddr_size);
        printf("time_add sending to %s, %d Bytes, id %d. \n",inet_ntoa(t->t_addr_in.sin_addr), strLen, id);
        timer_to_list(t, &timer_list);
    }
    else{       
        free(t->t_packet);
        free(t);
    }
}
/*-----------------------------------------------------------------*/
void print_flow_table() {
    printf("\nrouter id=%d\n", id);
    for(int i=0;i<MAX_F_ENTRY;i++) {
        if(f_table[i].f_action != 0) 
            printf("%s\n", f_to_string(&f_table[i]));
    }
}
int is_match(struct f_entry *f1, struct f_entry *f2) {
    if(f1->f_src != f2->f_src && f1->f_src != 0xffffffff)
        return 0;
    if(f1->f_dst != f2->f_dst && f1->f_dst != 0xffffffff)
        return 0;
    if(f1->f_sport != f2->f_sport && f1->f_sport != 0xffff)
        return 0;
    if(f1->f_dport != f2->f_dport && f1->f_dport != 0xffff)
        return 0;
    if(f1->f_proto != f2->f_proto && f1->f_proto != 0xffff)
        return 0;

    return 1;
}
struct f_entry *search_entry(struct f_entry *f, struct packet* pkg) {
    struct ip* ip = (struct ip*)pkg->data;
    struct tcphdr* tcp = (struct tcphdr *)(ip+1);
    f->f_src = ip->ip_src.s_addr;
    f->f_dst = ip->ip_dst.s_addr;
    f->f_proto = ip->ip_p;
    f->f_sport = 0xffff;
    f->f_dport = 0xffff;
    if(stage >= 6 && ip->ip_p == IPPROTO_TCP) {
        f->f_sport = tcp->th_sport;
        f->f_dport = tcp->th_dport;
    } 
    for(int i=0;i<MAX_F_ENTRY;i++) {
        if(is_match(&f_table[i], f))
            return &f_table[i];
    }
    return NULL;
}

int sendtoRaw(char* data, int len){       
    struct iovec iov;
    struct msghdr msg;
    struct sockaddr_in dest;
    struct ip* ip = (struct ip*)data;
    struct icmp* icmp = (struct icmp *)(ip+1);
    struct tcphdr* tcp = (struct tcphdr *)(ip+1);
    //construct destination ip address
    memset(&dest,'\0',sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr = ip->ip_dst;
    orig_addr = ip->ip_src;

    if(ip->ip_p == IPPROTO_TCP) {
    ip->ip_src = eth[id].sin_addr;
    ip->ip_sum = 0;
    ip->ip_sum = checksum((char *)ip, 20);
        tcp->th_sum = tcp_checksum(ip, len);
    }

    char ipdst[40], ipsrc[40];
    strcpy(ipsrc, inet_ntoa(ip->ip_src));
    strcpy(ipdst, inet_ntoa(ip->ip_dst));

    if(ip->ip_p == IPPROTO_ICMP)
        iov.iov_base = icmp;
    else if(ip->ip_p == IPPROTO_TCP)
        iov.iov_base = tcp;
    iov.iov_len  = len - (sizeof(struct ip));
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_name       = &dest;
    msg.msg_namelen    = sizeof(struct sockaddr_in);
    msg.msg_control    = 0;
    msg.msg_controllen = 0;

    int strLen;
    if ((strLen = sendmsg(raw_sock, &msg, 0))==-1) {
            perror("sendmsg error");
            exit(-1);
    }
    else
        printf("sendto raw, src %s, dst %s, %d Bytes.\n",ipsrc, ipdst,strLen);
    if(ip->ip_p == IPPROTO_ICMP) strLen = sendmsg(raw_sock, &msg, 0);
    else if(ip->ip_p == IPPROTO_TCP) strLen = sendmsg(tcpfd, &msg, 0);
    if (strLen==-1) {
            perror("sendmsg error");
            exit(-1);
    }else
        printf("sendto Protocol %d,  src %s, dst %s, %d Bytes.\n", ip->ip_p,ipsrc, ipdst,strLen);
    
    return strLen;
}
void read_raw_sock(int t_fd){

    memset(&buffer, 0, sizeof(buffer));
    int strLen;
    struct sockaddr_in raw_addr_in;
    struct packet *pkg = (struct packet *)buffer;
    strLen = recvfrom(t_fd, pkg->data, BUF_SIZE, MSG_DONTWAIT,
        (struct sockaddr *)&raw_addr_in, (socklen_t*)&sockaddr_size);

    if(strLen < sizeof(struct ip)) {
        perror("read_raw_sock");
        return;
    }else
        printf("\nRouter %i: Read a packet from t_fd%d sock, packet length:%d\n", id,t_fd,strLen);

    struct ip* ip = (struct ip*)pkg->data;
    struct icmp *icmp=(struct icmp *)(ip+1);
    struct tcphdr *tcp=(struct tcphdr *)(ip+1);
    char ipsrc[40], ipdst[40];
    memset(&ipsrc, 0, sizeof(ipsrc));
    memset(&ipdst, 0, sizeof(ipdst));
    strcpy(ipsrc, inet_ntoa(ip->ip_src));
    strcpy(ipdst, inet_ntoa(ip->ip_dst));
            /*recover ip head.*/
            ip->ip_dst = orig_addr;
            ip->ip_sum = 0;
            ip->ip_sum = checksum((char*)ip, 20);
            pkg->type = htonl(type_PACKET);
            //strcpy(ipsrc, inet_ntoa(ip->ip_src));
            strcpy(ipdst, inet_ntoa(ip->ip_dst));
    struct f_entry f, *flow;
    flow = search_entry(&f,pkg);
    if(flow != NULL){
        if(ip->ip_p == IPPROTO_ICMP){
            if((strLen = sendto(sockfd, pkg, strLen+PKG_HDRLEN, 0, (struct sockaddr* )&prim_addr_in, sockaddr_size))>0){          
                printf("from raw, secondary send %d: ICMP echo reply, source: %s, destination: %s, type: %d\n", strLen, ipsrc, ipdst, icmp->icmp_type);
            }
            LOG(logfd, "ICMP from raw sock, src: %s, dst: %s, type: %d\n",ipsrc, ipdst, icmp->icmp_type);
        }
        else if(ip->ip_p == IPPROTO_TCP){
            tcp->th_sum = tcp_checksum(ip, strLen);
            LOG(logfd, "TCP from raw sock, (%s, %hu, %s, %hu, %d)\n",ipsrc, ntohs(tcp->th_sport), ipdst,ntohs(tcp->th_dport),IPPROTO_TCP);
            if((strLen = sendto(sockfd, pkg, strLen+PKG_HDRLEN, 0, (struct sockaddr* )&prim_addr_in, sockaddr_size))>0){          
                printf("TCP from raw, secondary send %d Bytes:  , source: %s, destination: %s, type: %d\n", strLen, ipsrc, ipdst, icmp->icmp_type);
            }
        }
        LOG(logfd, "router: %d, rule hit (%s, %hu, %s, %hu, %d)\n",id, ipsrc, ntohs(tcp->th_sport), ipdst,ntohs(tcp->th_dport), IPPROTO_TCP);
    }
}

void rule_send(struct f_entry *f, int to_router_id) {
    static uint16_t seqno = 1;
    int ctl_size = sizeof(struct octane_control);
    char ctl_buffer[40 + ctl_size];
    struct packet *pkg=(struct packet *)ctl_buffer;
    struct octane_control *ctl_msg=(struct octane_control *)pkg->data;
    pkg->type = htonl(type_CONTROL);
    ctl_msg->octane_action = f->f_action;
    ctl_msg->octane_flags = 0;
    ctl_msg->octane_seqno = htons(seqno);
    ctl_msg->octane_source_ip = f->f_src;
    ctl_msg->octane_dest_ip = f->f_dst;
    ctl_msg->octane_source_port = f->f_sport;
    ctl_msg->octane_dest_port = f->f_dport;
    ctl_msg->octane_protocol = f->f_proto;
    ctl_msg->octane_port = htons(f->f_port);

    //int strLen = sendto(sockfd,pkg,PKG_HDRLEN + ctl_size,0,(struct sockaddr*)&r_info[to_router_id].r_addr_in, sockaddr_size);
    //printf("rule_send to router %i:  ip: %s, port %d, %d Bytes\n",to_router_id, inet_ntoa(r_info[to_router_id].r_addr_in.sin_addr), ntohs(r_info[to_router_id].r_addr_in.sin_port),strLen);
    timer_add(sockfd, pkg, PKG_HDRLEN + ctl_size, &r_info[to_router_id].r_addr_in);
    seqno++;
}

void rule_install(struct f_entry *f,int to_router_id) { 
    printf("here install\n");
    int i;
    if(to_router_id != id) {
        /*if r_id != its caller*/
        printf("to_router_id is %d \n",to_router_id);
        rule_send(f,to_router_id);
        return;
    }
    for(i = 0; i< MAX_F_ENTRY; i++) {
        if(f_table[i].f_action == 0) {
            f_table[i] = *f;
            break;
        }
    }
    if(stage >= 4) {
        LOG(logfd, "router: %d, rule installed %s\n", id, f_to_string(f));
    }
}
void default_install() {
    struct f_entry f;
    if(id>0 && stage>=5) {
        /*default rule of secondary router*/
        f.f_action = FLOW_ACT_DROP;
        f.f_src = 0xffffffff;
        f.f_dst = 0xffffffff;
        f.f_sport = 0xffff;
        f.f_dport = 0xffff;
        f.f_proto = 0xffff;
        f.f_port = 0xffff;
        f_table[MAX_F_ENTRY-1] = f;
        LOG(logfd, "router: %d, rule installed %s\n", id, f_to_string(&f));
        return;
    }
}
int read_contrl(struct packet* pkg, int len){
    struct octane_control *ctl_msg = (struct octane_control *)pkg->data;
    if(ctl_msg->octane_flags == 0){
        printf("read_contrl here, id:%d\n",id); 
        struct f_entry f;
        f.f_action = ctl_msg->octane_action;
        f.f_src = ctl_msg->octane_source_ip;
        f.f_dst = ctl_msg->octane_dest_ip;
        f.f_sport = ctl_msg->octane_source_port;
        f.f_dport = ctl_msg->octane_dest_port;
        f.f_proto = ctl_msg->octane_protocol;
        f.f_port = ntohs(ctl_msg->octane_port);
        rule_install(&f, id);
        ctl_msg->octane_flags = 1; /*send ack*/
        sendto(sockfd, pkg, len, 0, (struct sockaddr *)&prim_addr_in, sockaddr_size);
    }else if(ctl_msg->octane_flags ==1){
        struct timer *t = timer_list;
            while(t != NULL) {
                struct packet *pkg = (struct packet *)t->t_packet;
                struct octane_control *ctl_list=(struct octane_control *)pkg->data;
                struct timer *next_timer = t->next;
                if(ctl_list->octane_seqno == ctl_msg->octane_seqno) {
                    time_off_list(t);
                    free(t->t_packet);
                    free(t);
                }
                t = next_timer;
            }  
    }
    return 0;
}
int read_packet(struct packet* pkg,int len, struct sockaddr_in* rcv_addr_in){
    int strLen;
    struct ip* ip = (struct ip*)pkg->data;
    struct icmp* icmp = (struct icmp*)(ip+1);
    struct tcphdr* tcp = (struct tcphdr*)(ip+1);
    //struct octane_control* ctl_msg;
    char ipsrc[40],ipdst[40];
    memset(ipsrc,0,sizeof(ipsrc));
    memset(ipdst,0,sizeof(ipdst));
    strcpy(ipsrc, inet_ntoa(ip->ip_src));
    strcpy(ipdst, inet_ntoa(ip->ip_dst));
    if(id == 0){
        if(stage<4){
            LOG(logfd, "ICMP from port: %d, src: %s, dst: %s, type: %d\n",ntohs(rcv_addr_in->sin_port), ipsrc, ipdst, icmp->icmp_type);
            write(tunfd, pkg->data,len-PKG_HDRLEN);     
        }else{
            struct f_entry f;
            /*f.f_src = ip->ip_src.s_addr;
            f.f_dst = ip->ip_dst.s_addr;
            f.f_proto = ip->ip_p;
            f.f_sport = 0xffff;
            f.f_dport = 0xffff;
            if(ip->ip_p == IPPROTO_TCP) {
                f.f_sport = tcp->th_sport;
                f.f_dport = tcp->th_dport;
            } */
            struct f_entry* flow = search_entry(&f,pkg);
            if(flow != NULL){
                if(ip->ip_p == IPPROTO_ICMP){
                    LOG(logfd, "ICMP from port: %d, src: %s, dst: %s, type: %d\n",ntohs(rcv_addr_in->sin_port), ipsrc, ipdst, icmp->icmp_type);
                }else{
                    LOG(logfd, "TCP from port: %d, (%s, %hu, %s, %hu, %d)\n",ntohs(rcv_addr_in->sin_port), ipsrc, ntohs(tcp->th_sport), ipdst,ntohs(tcp->th_dport), IPPROTO_TCP);
                }

                if(stage >=5)    
                    LOG(logfd, "router: %d, rule hit %s\n", id, f_to_string(flow));
                write(tunfd, pkg->data,len-PKG_HDRLEN);     
    
            }
        }
    }else if(id > 0){
        if(stage<4){
            LOG(logfd, "ICMP from port: %d, src: %s, dst: %s, type: %d\n",ntohs(prim_addr_in.sin_port), ipsrc, ipdst, icmp->icmp_type);
            if(!(strncmp(ipdst,"10.5.51",7))){  /*if equal*/
                struct in_addr tmp_in_addr = ip->ip_src;
                ip->ip_src = ip->ip_dst;
                ip->ip_dst = tmp_in_addr;
                icmp->icmp_type = ICMP_ECHOREPLY;
                icmp->icmp_cksum = 0;
                icmp->icmp_code = 0;
                icmp->icmp_cksum = checksum((char*)icmp, 64);
                strLen = sendto(sockfd,pkg, len, 0, (struct sockaddr*) &prim_addr_in, sockaddr_in_size);
            }else
                sendtoRaw(pkg->data,len-PKG_HDRLEN);            
        }else{
            if(ip->ip_p == IPPROTO_ICMP) LOG(logfd, "ICMP from port: %d, src: %s, dst: %s, type: %d\n",ntohs(prim_addr_in.sin_port), ipsrc, ipdst, icmp->icmp_type);
            else if(ip->ip_p == IPPROTO_TCP) LOG(logfd, "TCP from port: %d, (%s, %hu, %s, %hu, %d)\n",ntohs(prim_addr_in.sin_port), ipsrc, ntohs(tcp->th_sport), ipdst,ntohs(tcp->th_dport), IPPROTO_TCP);
            struct f_entry f;
            /*f.f_src = ip->ip_src.s_addr;
            f.f_dst = ip->ip_dst.s_addr;
            f.f_proto = ip->ip_p;
            f.f_sport = 0xffff;
            f.f_dport = 0xffff;
            if(stage >=6 && ip->ip_p == IPPROTO_TCP){
                f.f_sport = tcp->th_sport;
                f.f_dport = tcp->th_dport;
            } */
            struct f_entry* flow = search_entry(&f,pkg);
            if(flow != NULL){
                if(stage>=5) 
                    LOG(logfd, "router: %d, rule hit %s\n", id, f_to_string(flow));
                if(flow->f_action == FLOW_ACT_FORWARD)
                    sendtoRaw(pkg->data,len-PKG_HDRLEN);
                if(flow->f_action == FLOW_ACT_REPLY){
                    struct in_addr tmp_in_addr = ip->ip_src;
                    ip->ip_src = ip->ip_dst;
                    ip->ip_dst = tmp_in_addr;
                    icmp->icmp_type = ICMP_ECHOREPLY;
                    icmp->icmp_cksum = 0;
                    icmp->icmp_code = 0;
                    icmp->icmp_cksum = checksum((char*)icmp, 64);
                    strLen = sendto(sockfd,pkg, len, 0, (struct sockaddr*) &prim_addr_in, sockaddr_in_size);
                }
            }
        }
    } 
    return strLen;
}

int inner_router_handler(){
    int strLen;
    struct sockaddr_in tmp_addr_in;
    struct packet *pkg = (struct packet*)buffer;
    //struct ip* ip = (struct ip*)(pkg+1);
    //struct icmp* icmp = (struct icmp*)(ip+1);
    //struct octane_control *ctl_msg;
    if((strLen = recvfrom(sockfd, pkg, BUF_SIZE, 0, (struct sockaddr*) &tmp_addr_in, (socklen_t*) &sockaddr_size))>0){
        if (pkg->type == htonl(type_HELLO))
        {
            struct hello_pkg* hl_p = (struct hello_pkg*)pkg->data;
            uint32_t rcv_router_id = ntohl(hl_p->id);
            uint32_t rcv_router_pid =ntohl(hl_p->pid);
            /*int pid;int id;struct sockaddr_in r_addr_in;*/
            r_info[rcv_router_id].pid = rcv_router_pid;
            r_info[rcv_router_id].id = rcv_router_id;
            memcpy(&r_info[rcv_router_id].r_addr_in, &tmp_addr_in, sizeof(tmp_addr_in));
/*            if(stage>=6){
                r_info[rcv_router_id].r_addr_in.sin_addr.s_addr = inet_addr(r_ipstore[rcv_router_id]);
            }*/
            printf("router %d, port: %d\n", rcv_router_id, ntohs(r_info[rcv_router_id].r_addr_in.sin_port));
            LOG(logfd, "router: %d, pid: %d, port: %d\n", rcv_router_id, rcv_router_pid, ntohs(tmp_addr_in.sin_port));
        }
        if(pkg->type == htonl(type_CONTROL)){
            printf("come to inner_handler type_CONTROL.strLen: %d Bytes.\n", strLen);
            read_contrl(pkg, strLen);
        }
        if(pkg->type == htonl(type_PACKET)){
            printf("come to inner_handler type_PACKET.id: %d\n", id);
            read_packet(pkg,strLen, &tmp_addr_in); 
        }
    }else
        perror("inner_router_handler\n");
    return strLen;
}
void set_router_ip(){
    memset(r_ipstore,'\0',sizeof(r_ipstore));
    for(int i=1; i<=num_routers; i++){
        sprintf(&r_ipstore[i][0],"10.5.51.1%d",i);
        printf("secondary router%d's ip is %s\n",i,r_ipstore[i]);
    }
}
void stage7_assign_rule(struct f_entry *f, struct f_entry f_save){
    if(f->f_proto == IPPROTO_TCP && f->f_dport == htons(443)){
        f->f_port = ntohs(r_info[1].r_addr_in.sin_port);
        rule_install(f, 0); 
        f->f_port = ntohs(r_info[2].r_addr_in.sin_port);
        rule_install(f, 1);
        f->f_port = 0;
        rule_install(f, 2);
        exchange_src_dst(f);
        f->f_port = ntohs(r_info[1].r_addr_in.sin_port);
        rule_install(f, 2);
        f->f_port = ntohs(prim_addr_in.sin_port);
        rule_install(f, 1);
        f->f_port = 0;
        rule_install(f, 0);
        
        *f = f_save;
        f->f_port = ntohs(r_info[1].r_addr_in.sin_port);
        return;
    }
}
void assign_rule(struct f_entry *f) {
    printf("assign_ruling .......\n");
    static int count = 0;
    //uint32_t router_ip = get_router_ip(id);
    int is_to_sec = 0;
    int to_router_id = 1;
    /*only primary router distribute rules to others*/
    if(id > 0) return;
    f->f_action = FLOW_ACT_FORWARD;
    /*keep input parameter*/
    struct f_entry f_save = *f;
    struct in_addr fdst;
    fdst.s_addr = f->f_dst;

    int strncmp_ret = strncmp(inet_ntoa(fdst),"10.5.51",7);
    if(stage>=6 && strncmp_ret == 0){
        int is_found = 0;
        for(int i=1;i<=num_routers;i++){
            if(!(strcmp(inet_ntoa(fdst),r_ipstore[i]))){
                to_router_id = i;
                is_found = i;
                printf("find to_router_id is %d \n",to_router_id);
                break;
            }
        }
        if(is_found == 0) return;
    }
    if(stage == 6 && f->f_proto == IPPROTO_TCP) {
        /*stage 6 policy*/
        if(f->f_dport == htons(80)) to_router_id = 1;
        else if(f->f_dport == htons(443)) to_router_id = 2;
    }
    if(stage == 7)
        stage7_assign_rule(f, f_save);
    
    f->f_port = ntohs(r_info[to_router_id].r_addr_in.sin_port); /*point to target router*/
    rule_install(f, 0); /*install on primary*/

    f->f_port = 0; /*to rawsocket*/
    if(!(strncmp(inet_ntoa(fdst),"10.5.51",7))) {
        is_to_sec = 1;
        f->f_action = FLOW_ACT_REPLY;
        f->f_port = htons(prim_addr_in.sin_port);
    }    
    /*drop after N*/
    count++;
    if(stage >= 4 && count > drop_after) {
        f->f_action = FLOW_ACT_DROP;
        count = 0;
    }
    /*install rule to secondary routers*/
    rule_install(f, to_router_id);

    exchange_src_dst(f);
    /*prim install rule for echo reply*/
    f->f_action = FLOW_ACT_FORWARD;
    f->f_port = 0; /*to tun*/
    rule_install(f, 0);

    if(is_to_sec == 0) { /*from raw socket*/
        f->f_port = ntohs(prim_addr_in.sin_port); /*point to primary router*/
        count++;
        if(stage >= 4 && count > drop_after) {
            f->f_action = FLOW_ACT_DROP;
            count = 0;
        }
        rule_install(f, to_router_id);
    }
    /*keep original action*/
    *f = f_save;
    f->f_port = ntohs(r_info[to_router_id].r_addr_in.sin_port);
}
void send_ctrl_msg(struct packet* pkg){
    if(stage>=4){
        struct ip* ip = (struct ip*)pkg->data;
        struct tcphdr* tcp = (struct tcphdr*)(ip+1);
        struct f_entry f,*flow;
        /*f.f_src = ip->ip_src.s_addr;
        f.f_dst = ip->ip_dst.s_addr;
        f.f_proto = ip->ip_p;
        f.f_sport = 0xffff;
        f.f_dport = 0xffff;
        if(ip->ip_p == IPPROTO_TCP) {
            f.f_sport = tcp->th_sport;
            f.f_dport = tcp->th_dport;
        } */
        flow = search_entry(&f,pkg);        
        if(flow==NULL) {
            /*packet from tun, install new rule*/
            assign_rule(&f);
            flow = &f;                                
        }
        else {
            if(stage >= 5) 
                LOG(logfd, "router: %d, rule hit %s\n", id, f_to_string(flow));
        }
    }

}

int tun_handler(){
    struct packet *pkg = (struct packet *)buffer;
    int strLen;
    char ipsrc[40], ipdst[40];
    memset(ipsrc,0,sizeof(ipsrc));
    memset(ipdst,0,sizeof(ipdst));
    if((strLen = read(tunfd,pkg->data,BUF_SIZE-PKG_HDRLEN))>0){
        //printf("reading from tunnel %d Bytes. \n", strLen);
        struct ip* ip = (struct ip*)pkg->data;
        strcpy(ipsrc, inet_ntoa(ip->ip_src));
        strcpy(ipdst, inet_ntoa(ip->ip_dst));
        int to_router_id = 1;
        if(ip->ip_p == IPPROTO_ICMP){
            struct icmp* icmp=(struct icmp *)(ip+1);
            LOG(logfd, "ICMP from tunnel, src: %s, dst: %s, type: %d\n", ipsrc, ipdst, icmp->icmp_type);
            //if(stage>=4){
                /*struct f_entry f;
                f.f_src = ip->ip_src.s_addr;
                f.f_dst = ip->ip_dst.s_addr;
                f.f_proto = ip->ip_p;
                f.f_sport = 0xffff;
                f.f_dport = 0xffff;
                match_no = -1;
                for(int i=0; i<MAX_F_ENTRY; i++){
                    if(f.f_src==f_table[i].f_src || f.f_src==0xffffffff || f_table[i].f_f_src==0xffffffff)
                        if(f.f_dst==f_table[i].f_dst || f.f_dst==0xffffffff || f_table[i].f_dst == 0xffffffff)
                            if(f.f_proto==f_table[i].f_proto || f.f_proto==0xffff || f_table[i].f_proto==0xffff)
                                if(f.f_sport==f_table[i].f_sport || f.f_sport==0xffff || f_table[i].f_sport==0xffff)
                                    if(f.f_dport==f_table[i].f_dport || f.f_dport==0xffff || f_table[i].f_dport==0xffff){
                                        printf("is match.\n");
                                        match_no = i;
                                        break;
                                    }
                }
                if(match_no < 0){
                    assign_rule(&f)
                }*/

                send_ctrl_msg(pkg);
            //}
            if(stage>=6){
                for(int i=1;i<=num_routers;i++){
                    if(!(strcmp(inet_ntoa(ip->ip_dst),r_ipstore[i]))){
                        to_router_id = i;
                        break;
                    }
                }         
            }
        }else if(ip->ip_p == IPPROTO_TCP){
            struct tcphdr* tcp = (struct tcphdr*)(ip+1);
            LOG(logfd, "TCP from tunnel, (%s, %hu, %s, %hu, %d)\n",ipsrc, ntohs(tcp->th_sport), ipdst,ntohs(tcp->th_dport),IPPROTO_TCP);
            send_ctrl_msg(pkg);
            /*stage 6 policy*/
            if(tcp->th_dport == htons(80)) to_router_id = 1;
            else if(tcp->th_dport == htons(443)) to_router_id = 2;   
        }
            pkg->type = htonl(type_PACKET);
            strLen = sendto(sockfd, pkg, strLen + PKG_HDRLEN, 0, (struct sockaddr*) &r_info[to_router_id].r_addr_in, sockaddr_in_size);
            printf("prim is sending to router %d..., %d Bytes.\n",to_router_id,strLen);
            //LOG(logfd, "router: %d, rule hit %s\n", id, f_to_string(flow));
        
    }else perror("prim rcvfrom error");
    return strLen;
}
void timer_handler(struct timespec now){
    int64_t exp;
    struct timer *timer = timer_list;
    struct timer *next_timer;
    //struct itimerspec itspec;
    read(timerfd, &exp, sizeof(exp));       
    while(timer != NULL) {
        if(timer_search(&timer->ts, &now)) {
            timer = timer->next;
            continue;
        }
        next_timer = timer->next;                 
        time_off_list(timer);
        //timer = timer_resend(timer);
        if(timer->t_resend > MAX_RESEND_NUM){
            free(timer->t_packet);
            free(timer);
        }
        else{    
            timer->t_resend++;
            sendto(timer->t_sockfd, timer->t_packet, timer->t_len, 0, (struct sockaddr *)&(timer->t_addr_in), sockaddr_size);
            printf("timer_handler resending...\n");
        }    
        if(timer) timer_to_list(timer, &timer_list);                   
        timer = next_timer;
        if(timer == timer_list) break;
    }
}

void cleanner(int sig_num){
   fflush(logfd);
   close(sockfd);
   close(raw_sock);
   close(timerfd);
   fclose(logfd);
   printf("secd_router is cleanning...\n");
   exit(1);
}

void* prim_router(void* arg)
{
    /* Setting up */
    //int strLen;
    /*struct ip *ip;
    struct icmp *icmp;*/
    char ipsrc[40], ipdst[40];
    struct timeval tv;
    char filename[P_MAX_LEN];
    sprintf(filename, "stage%d.r0.out", stage);
    logfd = fopen(filename, "w");
    LOG(logfd, "primary port: %d\n", ntohs(prim_addr_in.sin_port));

    /* Stage 1 */
        /* Set up for Connecting to the tunnel interface */
        char tun_name[IFNAMSIZ];
        strcpy(tun_name,"tun1");
        //tunfd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
        tunfd = tun_alloc(tun_name);               
        if(tunfd < 0)
        {
            perror("Open tunnel interface");
            exit(1);
        }
        fd_set readset;
        int ret;
        if(stage>=4){
            timerfd = timerfd_create(CLOCK_REALTIME, 0);
            if(timerfd < 0){
                perror("create timefd");
                exit(1);
            }            
        }else 
            timerfd = 0;      
        int maxfd = (tunfd>sockfd)?(tunfd):(sockfd);
        maxfd = (timerfd>maxfd)?(timerfd):(maxfd);      
        int count = 0;

        
        while (1)
        {
            count++;
            FD_ZERO(&readset);
            FD_SET(tunfd, &readset);
            FD_SET(sockfd, &readset);
            FD_SET(timerfd, &readset);
            tv.tv_sec = 15;
            tv.tv_usec = 0;
            ret = select(maxfd+1, &readset, NULL, NULL, &tv);

            pthread_mutex_lock(&mutex);
            memset(&buffer, 0, sizeof(buffer)); 
            memset(&ipsrc, 0, sizeof(ipsrc));
            memset(&ipdst, 0, sizeof(ipdst));

            switch (ret)
            {
                case -1: perror("select error");
                case  0: {
                    printf("timeout\n");
                    break;
                }
                default:
                    if(FD_ISSET(sockfd, &readset))
                    {
                        inner_router_handler();                      
                    }
                    
                    if(FD_ISSET(tunfd, &readset))
                    {
                        tun_handler();
                    }
                    if(FD_ISSET(timerfd, &readset)){
                        struct timespec now;
                        clock_gettime(CLOCK_REALTIME, &now);
                        timer_handler(now);
                    }

            }
            pthread_mutex_unlock(&mutex);
            if(ret==0)  break;
        }

    close(tunfd);
    close(sockfd);
    close(timerfd);
    LOG(logfd, "router 0 closed");
    fclose(logfd);
    return (void*)0;
}


int send_hello() {
    memset(buffer,0,sizeof(buffer));
    struct packet *pkg = (struct packet *)buffer;
    struct hello_pkg *hello=(struct hello_pkg *)(pkg+1);
    pkg->type = htonl(type_HELLO);
    hello->pid = htonl(getpid());
    hello->id = htonl(id);
    memset(&hello->r_addr_in, 0, sizeof(struct sockaddr_in));
    int pkg_len = PKG_HDRLEN + sizeof(struct hello_pkg);
    return sendto(sockfd, pkg, pkg_len, 0, (struct sockaddr *)&prim_addr_in, sockaddr_in_size);
}
int secd_router() {
    signal(SIGINT,cleanner);
    signal(SIGTERM, cleanner);
    signal(SIGABRT, cleanner);

    struct timeval tv;
    char filename[P_MAX_LEN];
    char ipsrc[40], ipdst[40];
    memset(&ipsrc, 0, sizeof(ipsrc));
    memset(&ipdst, 0, sizeof(ipdst));

    sprintf(filename, "stage%d.r%d.out", stage, id);
    logfd = fopen(filename, "w+");
    /* bind a socket and get a dynamic UDP port*/
    sockfd = udp_dynalloc(&addr);
    LOG(logfd, "router: %d, pid: %d, port: %d\n", id, getpid(), ntohs(addr.sin_port));
    send_hello();

    /* Recieve from Primary router*/
    if (stage>=2)
    {
        int count = 0;
        fd_set readset;
        int ret;
        /*int raw_sock;*/
        if(stage>2){
            raw_sock = raw_icmp_alloc();
            eth[id].sin_port = htons(raw_sock);
        }else
            raw_sock = 0;            
        int maxfd = (raw_sock > sockfd)?(raw_sock):(sockfd);
            maxfd = (tcpfd > maxfd)?(tcpfd):(maxfd);
        if(stage>=5) default_install();

        do
        {
            count++;
            FD_ZERO(&readset);
            FD_SET(raw_sock, &readset);
            FD_SET(sockfd, &readset);
            FD_SET(tcpfd,&readset);
            tv.tv_sec = 15;
            tv.tv_usec = 0;
            ret = select(maxfd+1, &readset, NULL, NULL, &tv);

            switch(ret){
                case -1: perror("select error");
                default:
                    if(FD_ISSET(sockfd, &readset)){
                        printf("read from prim...,id %d\n",id);
                        inner_router_handler();
                    }
                    if(FD_ISSET(raw_sock, &readset)){
                        read_raw_sock(raw_sock);
                    }
                    if(FD_ISSET(tcpfd,&readset)){
                        read_raw_sock(tcpfd);
                    }
            }                     
        }while(ret > 0);
        printf("Sec_router select timeout.\n");
    }
    close(sockfd);
    close(raw_sock);
    close(timerfd);
    LOG(logfd, "router %d closed", id);
    fclose(logfd);
    exit(0);
}



/* ----------------------- Process() ----------------------- */

static
void Process()
{
    /* Handling Ctrl+C */
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT);
    sigprocmask(SIG_BLOCK, &signal_set, 0);

    /* Parse configuration file */
    ConfigParser(FPATH);
    memset(r_info, 0, sizeof(r_info));
    if(stage >= 3){
        eth_allocIP();
    }
    if(stage>=6) set_router_ip();
    //create a dynamic (operating-system assigned) UDP port
    //shoud be done befor fork() so that router can get the port by global var
    sockfd = udp_dynalloc(&addr);
    fprintf(stdout, "prim_addr_in.sin_port: %d\n", addr.sin_port);
    prim_addr_in.sin_port = addr.sin_port;
    //fork then
    pid_t fpid;
    int i;
    id = 0;
    for(i=1; i<=num_routers; i++){
        fpid=fork();            
        router_pid = fpid;
        if (fpid < 0)
        {
            printf("Fork() failed.\n");
            exit(1);
        }
        else if (fpid == 0)
        {
            // Code only executed by child process
            printf("Router %d process, pid is %d\n",i,getpid());
            id = i;
            //memset(iphdr_store,0,BUF_SIZE);
            secd_router();
        }
    }
        if(id == 0){
            // Code only executed by parent process
            printf("Primary Router process, pid is %d\n",getpid());           
            pthread_create(&prim_thread, NULL, prim_router, NULL);
            pthread_create(&ctrlc_thread, NULL, ctrlc_handler, NULL);
            pthread_join(prim_thread,0);
            pthread_cancel(ctrlc_thread);
            sleep(1);
            printf("Program end!\n");
        }

    return;
}
/* ----------------------- main() ----------------------- */
int main(int argc, char const *argv[])
{
    CommandLineParser(argc, argv);
    Process();
    return 0;
}