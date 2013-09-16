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

#include "def.h"

pcap_t* descr;
pthread_t tid[2];
int sock, connected, bytes_recv = 0;
struct sockaddr_in local_addr, remote_addr;
socklen_t sin_size;
int error = 0;
unsigned short server_mode = 0;
char hostname[256] = {0};
char udpremote[256] = {0};
int port = 0;
unsigned short int tunorif = 0; /* [tun==1, if==2] */
int err;
char *tap_ip, *tap_mac, *tap_mask = NULL;
char *bpf = NULL;
char recv_data[MAX_PCAP_SIZ];
short int udpmode = 0;

void usage()
{
	fprintf(stderr, "Option -%c error.\n", optopt);
	fprintf(stderr, "*** tundeep by npn ***\n");
	#ifdef _LINUX
	fprintf(stderr, "Usage: tundeep <-i iface|-t tapiface> <-h ip> <-p port> <-c|-s> ");
	fprintf(stderr, "[-x tapip] [-y tapmask] [-u tapmac] [-b bpf] [-d udp mode] [-e udp remote]\n\n");
	#else
	fprintf(stderr, "Usage: tundeep [-a] <-i iface> <-h ip> <-p port> <-c|-s> ");
	fprintf(stderr, "[-b bpf] [-d udp mode] [-e udp remote]\n\n");
	#endif
	fprintf(stderr, "-a print all pcap devs\n");
	fprintf(stderr, "-b \"bpf\"\n");
	fprintf(stderr, "-i interface to bind to\n");
	fprintf(stderr, "-h IP to bind to/connect to\n");
	fprintf(stderr, "-p port to bind to/connect to\n");
	fprintf(stderr, "-c client mode\n");
	fprintf(stderr, "-s server mode\n");
	fprintf(stderr, "-d udp mode\n");
	#ifdef _LINUX
	fprintf(stderr, "-t tap interface \n");
	fprintf(stderr, "-u tap mac \n");
	fprintf(stderr, "-x if -t mode, set iface ip\n");
	fprintf(stderr, "-y if -t mode, set iface mask\n");
	#endif
	fprintf(stderr, "--------------------\n\n");
}

int main(int argc,char **argv)
{
	int c = 0;
	char iface[128] = {0};
	int actr = 0; char a[34];
	int i = 0, inum = 0;
	pcap_if_t *alldevsp, *device;
	char errbuf[PCAP_ERRBUF_SIZE];
	#ifdef _LINUX
	while ( ((c = getopt(argc, argv, "e:dai:t:u:h:p:csb:x:y:")) != -1) && (actr < 32) )
	#else
	while ( ((c = getopt(argc, argv, "e:dab:i:h:p:cs")) != -1) && (actr < 32) )
	#endif
	{
		a[actr] = c; actr++;
		switch(c)
		{
			case 'b':
				bpf = malloc(strlen(optarg)+1);
				strncpy(bpf, optarg, strlen(optarg));
				break;
			case 'a':
				//interface
				fprintf(stderr, "Printing device list:\n");
				fprintf(stderr, "---------------------\n");
				if (pcap_findalldevs(&alldevsp, errbuf))
				{
					debug(1, 1, "Error finding devices (%s)", errbuf);
				}
				for (device = alldevsp; device != NULL; device = device->next)
				{
					fprintf(stderr, "%d. %s", ++i, device->name);
					if (device->description)
					{
						fprintf(stderr, " (%s)\n", device->description);
					} else {
						fprintf(stderr, " (No description available)\n");
					}
				}
				fprintf(stderr, "---------------------\n");
				debug(1, 0, "Device list finished printing");
				printf("Enter the interface number (1-%d): ", i);
				if (scanf("%d", &inum)) { /* ssshh compiler */ }
				if (inum < 1 || inum > i)
				{
					fprintf(stderr, "\nInterface out of range\n");
					pcap_freealldevs(alldevsp);
					exit(0);
				}
				for (device=alldevsp, i=0; i < inum-1; device = device->next, i++);
				strncpy(iface, device->name, 127);
				tunorif = IFACE;
				break;
			case 'i':
				strncpy(iface, optarg, 127);
				tunorif = IFACE;
				break;
			case 'e':
				//host to listen on/connect to
				strncpy(udpremote, optarg, 255);
				break;
			case 'h':
				//host to listen on/connect to
				strncpy(hostname, optarg, 255);
				break;
			case 'p':
				//port
				port = atoi(optarg);
				break;
			case 'c':
				//client mode
				server_mode = 0;
				break;
			case 's':
				//server mode
				server_mode = 1;
				break;
			case 'd':
				udpmode = 1;
				break;
			#ifdef _LINUX
			case 't':
				//tap
				strncpy(iface, optarg, 127);
				tunorif = TUN;
				break;
			case 'u':
				//tap mac
				tap_mac = malloc(18);
				strncpy(tap_mac,optarg,17);
				break;
			case 'x':
				//tap ip
				tap_ip = malloc(16);
				strncpy(tap_ip, optarg, 15);
				break;
			case 'y':
				//tap mask
				tap_mask = malloc(16);
				strncpy(tap_mask, optarg, 15);
				break;
			#endif
			case '?':
				usage();
				debug(2, 1, "Usage error");
				break;
		}
	}
	a[actr]='\0';
	if ( ((strchr(a, 's') == NULL) && (strchr(a, 'c') == NULL)) && (strchr(a, 'd') == NULL) )
	{
		usage();
		fprintf(stderr, "Either -s or -c must be specified\n");
		debug(2, 1, "Usage error3");
	}
	if ( (strchr(a, 's') != NULL) && (strchr(a, 'c') != NULL) )
	{
		usage();
		fprintf(stderr, "Option -s and -c can not be specified together\n");
		debug(2, 1, "Usage error3");
	}
	if ( (strchr(a, 'h') == NULL) || (strchr(a, 'p') == NULL) )
	{
		usage();
		fprintf(stderr, "Options -h and -p are mandatory\n");
		debug(2, 1, "Usage error3");
	}
	if ( (strchr(a, 'd') != NULL) && (strchr(a, 'e') == NULL) )
	{
		usage();
		fprintf(stderr, "-e endpoint must be specified in UDP mode\n");
		debug(2, 1, "Usage error3");
	}
	if ( (strchr(a, 'd') != NULL) && ( (strchr(a, 'c') != NULL) || (strchr(a, 's') != NULL) ) )
	{
		usage();
		fprintf(stderr, "-c/-s not required in UDP mode\n");
		debug(2, 1, "Usage error3");
	}
	if ( (strchr(a, 'a') == NULL) && (strchr(a, 'i') == NULL) && (strchr(a, 't') == NULL) )
	{
		usage();
		fprintf(stderr, "Option -a, -i OR -t must be specified\n");
		debug(2, 1, "Usage error3");
	}
	if ( (strchr(a, 'a') != NULL) && (strchr(a, 'i') != NULL) && (strchr(a, 't') != NULL) )
	{
		usage();
		fprintf(stderr, "Option -a, -i and -t can not be specified together\n");
		debug(2, 1, "Usage error3");
	}
	if ( ( (strchr(a, 'a') != NULL) || (strchr(a, 'i') != NULL) ) && ( (strchr(a, 'u') != NULL) || (strchr(a, 'x') != NULL) || (strchr(a, 'y') != NULL) ))
	{
		usage();
		fprintf(stderr, "Options -u, -x and -y only work with -t, not -i or -a\n");
		debug(2, 1, "Usage error3");
	}

	#ifdef _LINUX
	if (tunorif == TUN)
	{
		//set up the tap device
		if ((tap_fd = tun_alloc(iface, IFF_TAP | IFF_NO_PI)) < 0)
		{
			perror("tun/tap failed");
		}
		confif(iface, tap_ip, tap_mask);
		if (tap_ip != NULL) { free(tap_ip); }
		if (tap_mask != NULL) { free(tap_mask); }
	}
	#endif

	/* First we set up PCAP */
	struct bpf_program fp;/* hold compiled program */
	bpf_u_int32 netp = 0; /* ip */

	/* open device for reading in promiscuous mode */
	descr = pcap_open_live(iface, MAX_PCAP_SIZ, 1,PCAP_TIMEOUT, errbuf);
	if(descr == NULL) {
		printf("pcap_open_live(): %s\n", errbuf);
		debug(2, 1, "pcap_open_live");
	}

	if (bpf == NULL)
	{
		bpf = malloc(1);
		memcpy(bpf, "\0", 1);
	}
	/* Now we'll compile the filter expression*/
	if(pcap_compile(descr, &fp,bpf, 0, netp) == -1) { //no search
		fprintf(stderr, "Error calling pcap_compile\n");
		debug(2, 1, "pcap_compile");
	}
	free(bpf);

	/* set the filter */
	if(pcap_setfilter(descr, &fp) == -1) {
		fprintf(stderr, "Error setting filter\n");
		debug(2, 1, "pcap filter");
	}

	/* Now we set up the socket */
	tun_connect(hostname, port);

	/* Now launch the threads */

        err = pthread_create(&(tid[0]), NULL, &thread_func, ""); //read from br0 and write to socket
        err = pthread_create(&(tid[1]), NULL, &thread_func, ""); //read from socket and write to br0

	for (;;) sleep(10); //don't terminate

	return 0;
}
