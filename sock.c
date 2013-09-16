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

int cread(int fd, char *buf, int n)
{
        int nread;
        if((nread=read(fd, buf, n))<0){
                debug(1, 1, "Error reading cread data");
        }
        return nread;
}

int cwrite(int fd, char *buf, int n)
{
	int nwrite = 0;
	if (udpmode)
	{
		if ((nwrite=sendto(fd, buf, n, 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr)))<0)
		{
			debug(1, 1, "Error writing cwrite data");
		}
	} else {
		if((nwrite=write(fd, buf, n))<0)
		{
			debug(1, 1, "Error writing cwrite data");
		}
	}
	return nwrite;
}

int read_n(int fd, char *buf, int n)
{
	int nread, left = n;
	while(left > 0)
	{
		if ((nread = cread(fd, buf, left))==0)
		{

			return 0;
		} else {
			left -= nread;
			buf += nread;
		 }
	}
	return n;
}



int tun_connect(char *hostname, int port)
{
        struct hostent *host;
	int optval = 1;

	if (udpmode)
	{
		sock = socket(AF_INET, SOCK_DGRAM, 0);
	} else {
		sock = socket(AF_INET, SOCK_STREAM, 0);
	}

	//local_addr will be the local end
	//remote_addr will be the remote end
	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_port = htons(port);
	remote_addr.sin_family = AF_INET;
	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sin_port = htons(port);
	local_addr.sin_family = AF_INET;
	if (!udpmode && server_mode)
	{
		host = gethostbyname(hostname);
		local_addr.sin_addr = *((struct in_addr *)host->h_addr);
	} else if (!udpmode && !server_mode) {
		host = gethostbyname(hostname);
		remote_addr.sin_addr = *((struct in_addr *)host->h_addr);
	} else if (udpmode) {
		host = gethostbyname(hostname);
		local_addr.sin_addr = *((struct in_addr *)host->h_addr);
		host = gethostbyname(udpremote);
		remote_addr.sin_addr = *((struct in_addr *)host->h_addr);
	}

	//if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval)) < 0)
	//{
	//	debug(1, 1, "setsockopt() failed");
	//}
	if (server_mode)
	{
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0)
		{
			debug(1, 1, "setsockopt() failed");
		}
		if (bind(sock, (struct sockaddr*) &local_addr, sizeof(local_addr)) < 0)
		{
			debug(1, 1, "bind() failed");
		}
	} else {
		if (!udpmode)
		{
			if (connect(sock, (struct sockaddr*) &remote_addr, sizeof(remote_addr)) < 0)
			{
				debug(1, 1, "connect() failed");
			}
		} else {
			if (bind(sock, (struct sockaddr*) &local_addr, sizeof(local_addr)) < 0)
			{
				debug(1, 1, "bind() failed");
			}
		}
	}
	return sock;
}
