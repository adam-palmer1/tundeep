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
unsigned int _tap_uncompress(char **dst, unsigned int ucompSize, char *comp, unsigned int compSize)
{
	//unsigned int nLength;
	//memcpy((char *)&nLength, comp, 4);
	*dst = malloc(ucompSize);
	//uncompress((Bytef *)*dst, (uLong *)&ucompSize, (Bytef *)comp+4, (uLong)ntohs(nLength));
	uncompress((Bytef *)*dst, (uLong *)&ucompSize, (Bytef *)comp, compSize);
	return ucompSize;
}

unsigned int _tap_compress(char **dst, const char *src, unsigned int len)
{
	uint32_t compSize = compressBound(len);
	uint32_t nLength = 0;

	*dst = malloc(compSize+sizeof(uint32_t));
	compress((Bytef *)*dst+(sizeof(uint32_t)), (uLong *)&compSize, (Bytef *)src, (uLong)len);
	nLength = htonl(compSize);
	memcpy(*dst, (char *)&nLength, sizeof(uint32_t));
	return compSize+sizeof(uint32_t);
}
#endif

void debug(int i, int quit, char *fmt, ...)
{
	if (DEBUG_LEVEL >= i)
	{
		va_list argptr;
		va_start(argptr, fmt);
		fprintf(stderr, "DEBUG(%d): ", i);
		vfprintf(stderr, fmt, argptr);
		fprintf(stderr, "\n");
		va_end(argptr);
	}
	if (quit)
	{
		exit(1);
	}
}

char *atoip(const char *ip)
{
	char *fip = malloc(4);
	unsigned int im[4];
	unsigned char bytes[4];
	sscanf(ip, "%u.%u.%u.%u", &im[0], &im[1], &im[2], &im[3]);
	bytes[0] = (unsigned char)im[0];
	bytes[1] = (unsigned char)im[1];
	bytes[2] = (unsigned char)im[2];
	bytes[3] = (unsigned char)im[3];
	memcpy(fip, bytes, 4);
	return fip;
}

char *iptoa(u_char *ip)
{
	char *oip = malloc(16);
	sprintf(oip, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
	return oip;
}

char *atom(const char *mac)
{
	//convert ascii mac to 6 byte mac
	unsigned int im[6] = {0};
	unsigned char m[6] = {0};
	short int ctr = 0;
	char *r = malloc(6);
	sscanf(mac, "%x:%x:%x:%x:%x:%x", &im[0], &im[1], &im[2], &im[3], &im[4], &im[5]);
	for (ctr = 0; ctr < 6; ctr++)
	{
		m[ctr] = (unsigned char)im[ctr];
	}
	memcpy(r, m, 6);
	return r;
}

char *mtoa(u_char *mac)
{
	//convert 6 byte mac to ascii mac
	unsigned char m[6];
	char *im = malloc(24);
	memcpy(m, mac, 6);
	sprintf(im, "%-.2X:%-.2X:%-.2X:%-.2X:%-.2X:%-.2X", m[0], m[1], m[2], m[3], m[4], m[5]);
	return im;
}

int check_ip(struct in_addr ip1, const char *ip2)
{
	struct in_addr ip2_addr;
	if (inet_pton(AF_INET, ip2, &ip2_addr) != 1)
	{
		return 0;
	}
	return ip1.s_addr == ip2_addr.s_addr;
}
