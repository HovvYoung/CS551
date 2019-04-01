#ifndef _COMMON_H_
#define _COMMON_H_

#define _GLIBCXX_USE_C99 1
#include <sys/timerfd.h>
#include<time.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>        /* Definition of uint64_t */
#include <string.h>
#include <linux/if_tun.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <math.h>
#include <ctype.h>


#ifndef NULL
#define NULL 0L
#endif /* ~NULL */

#ifndef TRUE
#define FALSE 0
#define TRUE 1
#endif /* ~TRUE */

#ifndef BUF_SIZE
#define BUF_SIZE 2000
#endif /* ~BUF_SIZE */

#ifndef MAXSIZE
#define MAXSIZE 2048
#endif /* ~MAXSIZE */

#ifndef P_MAX_LEN
#define P_MAX_LEN 256
#endif /* ~MAXPATHLENGTH */

#endif
