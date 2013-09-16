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

void send_received_packet(char *s, int plen)
{
	/* here we have an inbound packet from pcap or tap that we're about to send over the sock */
	int nwrite;
	unsigned int l;
	l = htons(plen);
	if (!server_mode)
	{
		connected = sock;
	}
	if ( ((server_mode && connected) || (!server_mode)) || (udpmode) )
	{
		nwrite = cwrite(connected, (char *)&l, sizeof(l));
		nwrite = cwrite(connected, s, plen);
		debug(4, 0, "sending packet of %d (%d) bytes", plen, nwrite);
	} else {
		debug(2, 0, "send_received_packet: No connected socket");
	}
}

#ifdef _LINUX
void read_loop()
{
	unsigned int nread;
	char *buffer = NULL;
	while (1)
	{
		buffer = malloc(MAX_PCAP_SIZ+1);
		nread = cread(tap_fd, buffer, MAX_PCAP_SIZ);
		debug(6, 0, "Read %d bytes from tapdev", nread);
		send_received_packet(buffer, nread);
		free(buffer);
	}
}
#endif

void pktrecv(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	if (arg == NULL) { /* silence compiler warning */ }
	send_received_packet((char *)packet, pkthdr->len);
}

void injection_process(int len, const u_char *packet)
{
	debug(5, 0, "Inject Handler Called");

	switch(tunorif)
	{
		case IFACE:
			if (pcap_sendpacket(descr, packet, len)==-1)
		        {
		                debug(1, 0, "error: pcap_sendpacket -1");
		        } else {
		                debug(5, 0, "packet sent");
		        }
			break;
		#ifdef _LINUX
		case TUN:
			if (!write(tap_fd, (char *)packet, len))
			{
				debug(3, 0, "tap_write error");
			}
			break;
		#endif
	}
}
