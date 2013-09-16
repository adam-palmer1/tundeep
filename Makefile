#Linux
CC=gcc

CFLAGS=-ggdb -I -O3 -Wall -W -D_LINUX -lpthread -lpcap 	#Linux
#CFLAGS=-ggdb -I -O3 -Wall -W -lpthread -lwpcap 	#Cygwin

tundeep: main.o pcap.o threads.o recv.o misc.o sock.o tap.o
	$(CC) -o tundeep main.o pcap.o threads.o recv.o misc.o sock.o tap.o $(CFLAGS)
clean:
	rm -f *.o tundeep
