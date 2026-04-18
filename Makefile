#Makefile for tundeep
#To disable Linux specific features i.e. tun/tap (not recommended), remove '-D_LINUX'
#To disable zlib compression support, remote '-D_COMPRESS -lz'

CC=gcc
MY_MACH := $(shell gcc -dumpmachine)
ifneq (, $(findstring cygwin, $(MY_MACH)))
	MY_OS := Cygwin
else
	MY_OS := Linux
endif

ifeq ($(MY_OS), Cygwin)
	#Cygwin
	CFLAGS=-s -O3 -Wall -W -D_COMPRESS
	LDFLAGS=-lz -lpthread -lwpcap
else
	#Linux
	CFLAGS=-s -O3 -Wall -W -D_LINUX -D_COMPRESS
	LDFLAGS=-lz -lpthread -lpcap
endif

tundeep: main.o pcap.o threads.o recv.o misc.o sock.o tap.o
	@echo "Building for: $(MY_OS) ($(MY_MACH))"
	$(CC) -o tundeep main.o pcap.o threads.o recv.o misc.o sock.o tap.o $(LDFLAGS)
clean:
	rm -f *.o tundeep tundeep.exe

