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

#ifdef _LINUX
int tap_fd = 0;

int tun_alloc(char *dev, int flags)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
	{
		perror("Opening /dev/net/tun");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = flags;

	if (*dev)
	{
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 )
	{
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
	return fd;
}

int confif(const char *ifname, const char *ip, const char *netmask)
{
	struct ifreq ifr;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
	char *tm;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ifr.ifr_addr.sa_family = AF_INET;

	if (ip != NULL)
	{
		inet_pton(AF_INET, ip, &addr->sin_addr);
		ioctl(fd, SIOCSIFADDR, &ifr);
	}
	if (netmask != NULL)
	{
		inet_pton(AF_INET, netmask, &addr->sin_addr);
		ioctl(fd, SIOCSIFNETMASK, &ifr);
	}

	if (tap_mac != NULL)
	{
		tm = atom(tap_mac);
		memcpy(ifr.ifr_hwaddr.sa_data, tm, 6);
		ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
		ioctl(fd, SIOCSIFHWADDR, &ifr);
		free(tm);
	}

	ioctl(fd, SIOCGIFFLAGS, &ifr);
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

	ioctl(fd, SIOCSIFFLAGS, &ifr);

	return 0;
}

struct in6_ifreq {
	struct in6_addr ifr6_addr;
	__u32 ifr6_prefixlen;
	unsigned int ifr6_ifindex;
};

int confif6(const char *ifname, const char *ip, const char *netmask)
{
	struct ifreq ifr;
	int fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);
	struct sockaddr_in6 addr;
	struct in6_ifreq ifr6;
	char *tm;
	int prefixlen = 64;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	memset(&addr, 0, sizeof(struct sockaddr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = 0;

	ifr.ifr_addr.sa_family = AF_INET6;

	if (ip != NULL)
	{
		if (inet_pton(AF_INET6, ip, (void *)&addr.sin6_addr) <= 0)
		{
			debug(1, 1, "Bad IPv6 address");
		}
		memcpy((char *) &ifr6.ifr6_addr, (char *) &addr.sin6_addr, sizeof(struct in6_addr));
		if (ioctl(fd, SIOGIFINDEX, &ifr) < 0)
		{
			perror("SIOGIFINDEX");
			debug(1, 1, "SIOGIFINDEX error");
		}
		ifr6.ifr6_ifindex = ifr.ifr_ifindex;
		if (netmask != NULL)
		{
			ifr6.ifr6_prefixlen = atoi(netmask);
		} else {
			ifr6.ifr6_prefixlen = prefixlen;
		}
		if (ioctl(fd, SIOCSIFADDR, &ifr6) < 0)
		{
			perror("SIOCSIFADDR");
			debug(1, 1, "SIOCSIFADDR error");
		}
	}


	if (tap_mac != NULL)
	{
		tm = atom(tap_mac);
		memcpy(ifr.ifr_hwaddr.sa_data, tm, 6);
		ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
		ioctl(fd, SIOCSIFHWADDR, &ifr);
		free(tm);
	}

	ioctl(fd, SIOCGIFFLAGS, &ifr);
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

	ioctl(fd, SIOCSIFFLAGS, &ifr);

	return 0;
}
#endif
