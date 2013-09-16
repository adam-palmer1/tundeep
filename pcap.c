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
	uint32_t l;
	l = htonl(plen);
	#ifdef _COMPRESS
	char *tmpbuf;
	char *compbuf;
	unsigned int complen;
	#endif
	if (!server_mode)
	{
		connected = sock;
	}
	if ( ((server_mode && connected) || (!server_mode)) || (udpmode) )
	{
		if (cksum)
		{
			nwrite = cwrite(connected, PREAMBLE, sizeof(PREAMBLE)-1);
			debug(6, 0, "Wrote %d byte preamble", nwrite);
		}
		#ifdef _COMPRESS
		if (!compmode)
		{
		#endif
			nwrite = cwrite(connected, (char *)&l, sizeof(l));
			nwrite = cwrite(connected, s, plen);
			debug(4, 0, "sending packet of %d (%d) bytes", plen, nwrite);
		#ifdef _COMPRESS
		} else {
			//sending compressed packet
			tmpbuf = malloc(plen+sizeof(uint32_t));
			memcpy(tmpbuf, (char *)&l, sizeof(uint32_t));
			memcpy(tmpbuf+(sizeof(l)), s, plen);
			complen = _tap_compress(&compbuf, tmpbuf, plen+sizeof(l));
			l = htonl(complen);
			nwrite = cwrite(connected, (char *)&l, sizeof(l));
			nwrite = cwrite(connected, compbuf+(sizeof(l)), complen);

			debug(4, 0, "sending compressed packet was %d now %d (%d)", plen, complen, nwrite);
			free(compbuf);
			free(tmpbuf);
		}
		#endif
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
		                debug(1, 0, "error: pcap_sendpacket (%d), -1", len);
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
