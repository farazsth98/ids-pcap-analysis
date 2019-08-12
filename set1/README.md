# Pcap \#1

* The packets are all ethernet packets

* One is a CDP packet which is sent out by Cisco devices. This tells us there is a Cisco device (switch/router) in this set of data

* A DNS query and a successful response for picard.uthscsa.edu (129.111.30.27)

* There are keepalive packets that the Cisco device sends itself every 10 seconds to make sure the connection is still valid (otherwise it would disconnect)



* There is a fragmented IPv4 packet which is reassembled in frame 9 and turns out to be a UDP packet with a bad length that is greater than the IP payload length. In this case however, we can see that the fragment offset of the first packet is set to 0. 

  I read up on Teardrop attacks and found out that if the sum of the fragment offset and the size of one fragmented packet differs from the next fragmented packet, the packets overlap and a server vulnerable to teardrop attacks will not be able to reassemble the packets, resulting in a DoS.

  In this case, first fragment at frame 8 has an offset of 0 and a size of 70 bytes. Second fragment at frame 9 has a size of 38 bytes, which is less than the sum of the offset and size of the previous fragmented packet, therefore I assume this was an attempt of a teardrop attack that failed because the OS that it targetted is not vulnerable to this attack.



* AddtronT sends out four ARP requests to Toshiba_cf to find out which machine has the IP 10.0.0.254, Toshiba_cf doesn't respond. AddtronT then sounds out a broadcast ARP request and Toshiba_cf finally responds and lets AddtronT know that Toshiba_cf has the IP 10.0.0.254. From this, I can tell that the Cisco switch/router's ARP table deleted the entry for Toshiba_cf which is why a broadcast was required.

* After the ARP requests succeed, Toshiba_cf pings AddtronT and gets a reply back.



# Pcap \#6

This just looks like a pcap file that has information regarding one user talking to a Gopher service on another server.

* Gopher service is at IP 192.168.195.100, Another one is T 86.43.88.90

* The user making requests to the IP is at 192.168.190.20

* Gopher is running on Port 70 for both IPs

* Each connection seems to run for around under a second and exchanges about the amount of data you'd expect

* Seems benign to me