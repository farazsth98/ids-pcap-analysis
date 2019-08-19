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




# Pcap \#2

On first glance, there are 622 requests over 29 seconds. That is about 21-22 packets per second, which is a lot.

* Looking at the packets and sorting the Info tab alphabetically, we see that it is definitely an ARP storm attack. We know this because there are multiple ARP requests for IP addresses in a sequential order in a couple different subnets.

* Because of the sequential order that the IPs are checked, it looks like someone is trying to do some reconnaisance to find what devices exist in each of the local subnets.

* There aren't enough packets to cause a Denial of Service though. 




# Pcap \#3

We only have one packet to analyse..

* This packet has an invalid checksum value.

* The data is just "hello world\n".

* The packet itself has a padding of 6 null bytes.

* The protocol is defined as Lightweight UDP, however the port that it usually runs on is 136, and this one is running on port 1234. I would definitely not trust this service.



# Pcap \#4

This pcap file mostly has TCP packets, but there are two DNS packets and 4 HTTP packets.

* 65.208.228.223 sent 34 packets to 145.254.160.237, but received 0 packets back. That is a bit weird.

* There are two HTTP GET requests and two HTTP 200 responses.

* The first GET request is for `/download.html` at the host `ethereal.com` and this is what transfers the bulk of the data. The second one is for an ad from google (that is probably on the page).

* The connection takes 13 seconds to terminate after the first FIN packet gets sent. I think that's weird? Taking 13 seconds for a connection to terminate.



# Pcap \#5

This seems like a pcap file that has data on two different devices trying to communicate with PPP. 

* It looks like someone is trying to authenticate as the user "Tyson"

* They try to authenticate twice, with two different fields as "values". The attempt fails both times.

* The connection then just terminates. Nothing unusual here.


# Pcap \#6

This just looks like a pcap file that has information regarding one user talking to a Gopher service on another server.

* Gopher service is at IP 192.168.195.100, Another one is T 86.43.88.90

* The user making requests to the IP is at 192.168.190.20

* Gopher is running on Port 70 for both IPs

* Each connection seems to run for around under a second and exchanges about the amount of data you'd expect

* Seems benign to me



# Pcap \#7

* Just a bunch of DNS requests.

* There is only one where the user (whoever they are) looks for www.example.notginh, which could be someone potentially testing to see whether the DNS server is actually working (or something like that?).

* There is also a couple where the user tries to resolve ip addresses for a couple of DNS addresses that seem to be on a local network, where one is an ldap server, and the other is GRIMM.utelsystems.local. Utel Systems seems to be an organization that creates software for analyzing networks.

* Nothing looks malicious here though.


# Pcap \#8

* Majority of the packets here are SMTP packets. Someone logs in to their email at xc90.websitewelcome.com. Email is `gurpartap@patriots.in` and password is `punjab@123`. 

* He sends an email to someone named Raj Deol with an smtp pcap file attached. Raj Deol's email is `raj_deol2002in@yahoo.co.in`.

* Everything is encoded in base64 (well most of the things).



# Pcap \#9

* There's only one UDP packet whose payload contains the string "this leeto string will crash your little nameserver for sure hahahahah"

* Based on the fact that this is the only UDP packet, I think it's safe to assume it did crash the server.



