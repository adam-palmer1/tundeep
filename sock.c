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
		if (ipv6)
		{
			if ((nwrite=sendto(fd, buf, n, 0, (struct sockaddr *)&remote_addr6, sizeof(remote_addr6)))<0)
			{
				perror("sendto");
				debug(1, 1, "Error writing cwrite data");
			}
		} else {
			if ((nwrite=sendto(fd, buf, n, 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr)))<0)
			{
				perror("sendto");
				debug(1, 1, "Error writing cwrite data");
			}
		}
	} else {
		if((nwrite=write(fd, buf, n))<0)
		{
			perror("write");
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
	int optval = 1;
	int af = AF_INET; int s = SOCK_STREAM;

	if (udpmode) s = SOCK_DGRAM;
	if (ipv6) af = AF_INET6;

	sock = socket(af, s, 0);

	//local_addr will be the local end
	//remote_addr will be the remote end
	if (!ipv6)
	{
		memset(&remote_addr, 0, sizeof(remote_addr));
		remote_addr.sin_port = htons(port);
		remote_addr.sin_family = AF_INET;
		memset(&local_addr, 0, sizeof(local_addr));
		local_addr.sin_port = htons(port);
		local_addr.sin_family = AF_INET;
	} else {
		memset(&remote_addr6, 0, sizeof(remote_addr6));
		remote_addr6.sin6_port = htons(port);
		remote_addr6.sin6_family = AF_INET6;
		memset(&local_addr6, 0, sizeof(local_addr6));
		local_addr6.sin6_port = htons(port);
		local_addr6.sin6_family = AF_INET6;
	}

	if (!ipv6)
	{
		if (!udpmode && server_mode)
		{
			if (!lookup_host (hostname, &local_addr)) { debug(1, 1, "Host lookup failed"); }
		} else if (!udpmode && !server_mode) {
			if (!lookup_host (hostname, &remote_addr)) { debug(1, 1, "Host lookup failed"); }
		} else if (udpmode) {
			if (!lookup_host (hostname, &local_addr)) { debug(1, 1, "Host lookup failed"); }
			if (!lookup_host (udpremote, &remote_addr)) { debug(1, 1, "Host lookup failed"); }
		}
	} else {
		if (!udpmode && server_mode)
		{
			if (!lookup_host6 (hostname, &local_addr6)) { debug(1, 1, "Host lookup failed"); }
		} else if (!udpmode && !server_mode) {
			if (!lookup_host6 (hostname, &remote_addr6)) { debug(1, 1, "Host lookup failed"); }
		} else if (udpmode) {
			if (!lookup_host6 (hostname, &local_addr6)) { debug(1, 1, "Host lookup failed"); }
			if (!lookup_host6 (udpremote, &remote_addr6)) { debug(1, 1, "Host lookup failed"); }
		}
	}

	if (server_mode)
	{
		//if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval)) < 0)
		//{
		//	debug(1, 1, "setsockopt() failed");
		//}
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0)
		{
			debug(1, 1, "setsockopt() failed");
		}
		if (!ipv6)
		{
			if (bind(sock, (struct sockaddr*) &local_addr, sizeof(local_addr)) < 0)
			{
				debug(1, 1, "bind() failed");
			}
		} else {
			if (bind(sock, (struct sockaddr *) &local_addr6, sizeof(local_addr6)) < 0)
			{
				debug(1, 1, "bind() failed");
			}
		}
	} else {
		if (!udpmode)
		{
			if (!ipv6)
			{
				if (connect(sock, (struct sockaddr*) &remote_addr, sizeof(remote_addr)) < 0)
				{
					debug(1, 1, "connect() failed");
				}
			} else {
				if (connect(sock, (struct sockaddr*) &remote_addr6, sizeof(remote_addr6)) < 0)
				{
					debug(1, 1, "connect() failed");
				}
			}
		} else {
			if (!ipv6)
			{
				if (bind(sock, (struct sockaddr*) &local_addr, sizeof(local_addr)) < 0)
				{
					debug(1, 1, "bind() failed");
				}
			} else {
				if (bind(sock, (struct sockaddr*) &local_addr6, sizeof(local_addr6)) < 0)
				{
					debug(1, 1, "bind() failed");
				}
			}
		}
	}
	return sock;
}

int lookup_host (const char *host, struct sockaddr_in *r)
{
	struct addrinfo hints, *res;
	int errcode;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	errcode = getaddrinfo (host, NULL, &hints, &res);
	if (errcode != 0)
	{
		perror ("getaddrinfo");
		return 0;
	}

	while (res)
	{
		if (res->ai_family == AF_INET)
		{
			r->sin_addr = ((struct sockaddr_in *) res->ai_addr)->sin_addr;
			return 1;
		}
		res = res->ai_next;
	}
	return 0;
}

int lookup_host6 (const char *host, struct sockaddr_in6 *r)
{
	struct addrinfo hints, *res;
	int errcode;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	errcode = getaddrinfo (host, NULL, &hints, &res);
	if (errcode != 0)
	{
		perror ("getaddrinfo");
		return 0;
	}

	while (res)
	{
		if (res->ai_family == AF_INET6)
		{
			r->sin6_addr = ((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
			return 1;
		}
		res = res->ai_next;
	}
	return 0;
}
