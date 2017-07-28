/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ctype.h>
#include <stdarg.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef _LINUX
#include <netinet/if_ether.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#endif
#ifdef _COMPRESS
#include <zlib.h>
#endif

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#ifndef TUNDEEP_DEFINES
#define TUNDEEP_DEFINES

#define VER "1.0_20170728"
#define PCAP_TIMEOUT 10 //Decrease for better performance/high CPU usage. 10 is reasonable
#define MAX_PCAP_SIZ 65536
#define DEBUG_LEVEL 1 //max 6
#define IFACE 0
#define TUN 1
#define PREAMBLE "\xff\x00\x41\x46\xfe\x01\xfd\xf0"

#define ifreq_offsetof(x)  offsetof(struct ifreq, x)

void debug(int i, int quit, char *fmt, ...);
int recvdata(int s);
int recvdata_c(int s);
void *thread_func(void *arg);
//inline u_short in_cksum(u_short *addr, int len);
void pktrecv(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void usage();
int tun_connect(char *hostname, int port);
void injection_process(int len, const u_char *packet);
int tun_alloc(char *dev, int flags);
int confif(const char *ifname, const char *ip, const char *netmask);
int confif6(const char *ifname, const char *ip, const char *netmask);
char *atom(const char *mac);
char *mtoa(u_char *mac);
int check_ip(struct in_addr, const char *ip2);
char *atoip(const char *ip);
char *iptoa(u_char *ip);
void read_loop();
void send_received_packet(char *s, int len);
int cread(int fd, char *buf, int n);
int cwrite(int fd, char *buf, int n);
int read_n(int fd, char *buf, int n);
int lookup_host (const char *host, struct sockaddr_in *r);
int lookup_host6 (const char *host, struct sockaddr_in6 *r);
#ifdef _COMPRESS
unsigned int _tap_uncompress(char **dst, unsigned int ucompSize, char *comp, unsigned int compSize);
unsigned int _tap_compress(char **dst, const char *src, unsigned int len);
#endif

extern pcap_t* descr;
extern pthread_t tid[2];
extern int sock, connected, bytes_recv;
extern struct sockaddr_in local_addr, remote_addr;
extern struct sockaddr_in6 local_addr6, remote_addr6;
extern socklen_t sin_size;
extern unsigned short server_mode;
extern char hostname[256];
extern char udpremote[256];
extern int port;
extern unsigned short int tunorif;
extern int tap_fd;

extern char *tap_mac;
extern char *bpf;
extern short int udpmode;
extern short int ipv6;
extern short int compmode;
extern short int cksum;
#endif
