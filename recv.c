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

#ifdef _COMPRESS

char *rdata(int fd, int len)
{
	int nread;
	char *retbuf = malloc(len);
	if (udpmode)
	{
		nread = recvfrom(fd, retbuf, len, 0, NULL, NULL);
	} else {
		nread = read_n(fd, retbuf, len);
	}

	if (nread == 0)
	{
		debug(1, 1, "nread == 0");
	}
	return retbuf;
}

int findcksum(int fd)
{
	unsigned int ctr = 0;
	int fullmatch = 0;
	char *c;
	int iter = 0;
	while (!fullmatch)
	{
		c = rdata(fd, sizeof(PREAMBLE)-1);
		fullmatch = 1;
		while (ctr < (sizeof(PREAMBLE)-1))
		{
			if (c[ctr] != PREAMBLE[ctr])
			{
				fullmatch = 0;
			}
			ctr++;
		}
		if (fullmatch == 1)
		{
			debug(5, 0, "Preamble matched at iteration %d", iter);
			iter = 0;
		} else {
			debug(5, 0, "Preamble failed at iteration %d", iter);
			iter++; ctr = 0;
		}
		free(c);
	}
	return fd;
}

int recvdata_c(int s)
{
	//unsigned int _tap_uncompress(char **dst, unsigned int ucompSize, char *comp);

	char *tmp_pkt = NULL;
	char *recv_pkt = NULL;

	uint32_t plength = 0, p = 0;
	uint32_t clength = 0, c = 0;

	if (cksum)
	{
		findcksum(s);
	}

	recv_pkt = rdata(s, sizeof(clength));
	memcpy((char *)&clength, recv_pkt, sizeof(clength));
	c = ntohl(clength);
	free(recv_pkt);

	debug(4, 0, "compressed recvdata() packet of %d size", c);

	if ( (c < 1) || (c > MAX_PCAP_SIZ) )
	{
		debug(5, 0, "Broken size. Frame lost");
		//bad len
		//drop
	} else {
		tmp_pkt = rdata(s, c);
		//tmp_pkt now contains compressed data
		_tap_uncompress(&recv_pkt, MAX_PCAP_SIZ-1, tmp_pkt, c);
		memcpy((char *)&plength, recv_pkt, sizeof(uint32_t));
		p = ntohl(plength);

		if ( (p < 1) || (p > MAX_PCAP_SIZ) )
		{
			debug(5, 0, "Broken size. Frame lost");
			//bad len
			//drop
		} else {
			injection_process(p, (const u_char *)recv_pkt+sizeof(uint32_t));
		}
		free(recv_pkt);
		free(tmp_pkt);
	}
	return 0;
}
#endif

int recvdata(int s)
{
        char *recv_pkt = NULL;
	uint32_t plength = 0, p = 0;
	if (cksum)
	{
		findcksum(s);
	}
	recv_pkt = rdata(s, sizeof(plength));
	memcpy((char *)&plength, recv_pkt, sizeof(plength));
	free(recv_pkt);
	p = ntohl(plength);
	debug(4, 0, "recvdata() packet of %d size", p);
	if ( (p < 1) || (p > MAX_PCAP_SIZ) )
	{
		debug(5, 0, "Broken size. Frame lost");
		//something's gone wrong
		//ignore the packet
	} else {
		recv_pkt = rdata(s, p);
		injection_process(p, (const u_char *)recv_pkt);
		free(recv_pkt);
	}
	return 0;
}
