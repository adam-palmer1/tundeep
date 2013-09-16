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

int recvdata(int s)
{
        char recv_pkt[MAX_PCAP_SIZ];
	unsigned int plength = 0, p = 0;
	int nread = 0;
	if (udpmode)
	{
		nread = recvfrom(s, (char *)&plength, sizeof(plength), 0, NULL, NULL);
	} else {
		nread = read_n(s, (char *)&plength, sizeof(plength));
	}
	p = ntohs(plength);
	debug(4, 0, "recvdata() packet of %d size", p);
	if (nread == 0)
	{
		debug(1, 1, "nread == 0");
	}

	if (udpmode)
	{
		nread = recvfrom(s, recv_pkt, p, 0, NULL, NULL);
	} else {
		nread = read_n(s, recv_pkt, p);
	}
	injection_process(p, (const u_char *)recv_pkt);
	return 0;
}
