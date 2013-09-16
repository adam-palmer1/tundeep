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

void* thread_func(void *arg)
{
        pthread_t id = pthread_self();

	if (arg == NULL) { /* silence compiler warning */ }

	if(pthread_equal(id,tid[0]))
	{
		//this thread listens in on pcap if it's an iface, or it reads from tap
		if (tunorif==IFACE)
		{
			/* loop for callback function */
			//we're receiving a packet on eth1
			pcap_loop(descr, 0, pktrecv, NULL); //keep receiving forever
		} else {
			#ifdef _LINUX
			//read from tap
			read_loop();
			#endif
		}
	} else {
		//this thread reads from the socket
		//server
		if (server_mode)
		{
			while (1)
			{
				if (!udpmode)
				{
					//accept a client
					listen(sock,0);
					sin_size = sizeof(struct sockaddr_in);
					connected = 0;
					connected = accept(sock, (struct sockaddr *)&remote_addr,&sin_size);
					debug(3, 0, "Client connected %s:%d", inet_ntoa(remote_addr.sin_addr),ntohs(remote_addr.sin_port));
				} else {
					connected = sock;
				}
				while (1)
				{
					if (recvdata(connected) == -1) { debug(6, 0, "Breaking in server_recvdata_connected"); break; }
				}
			}
		} else {
			//client
			connected = sock;
			while (1)
			{
				if (recvdata(connected) == -1) { debug(6, 0, "Breaking in client_recvdata_connected"); break; }
			}
			debug(1, 0, "Client quitting");
		}
	}
	return NULL;
}
