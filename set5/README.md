# Pcap \#41
 
Looks benign to me. Just someone browsing the web, checking the weather, goes to some advertising website in Australia. Normal TLS, HTTP, and DNS traffic.

# Pcap \#42

Again, nothing weird about this either. Just some normal TLS and DNS traffic. At the beginning of the HTTP traffic there is a very weird looking POST request made to the root of a website, but I don't see anything bad come out of it so I'm gonna go with benign.

# Pcap \#43

There is one weird TCP packet sent to port 256, but nothing comes of it. The DNS and ARP traffic looks benign. The rest of the traffic uses TLS so it's encrypted. Even if something bad is going on there, we can't tell, thus we must conclude benign.

# Pcap \#44

Now this is weird. It looks like someone uses TFTP to read the contents of a web page named details.html . The web page seems to be something about "Building your own custom Kali ISO". Of course even though this is weird, the person doesn't seem to be doing anything malicious (building your own Kali ISO is not malicious), therefore we must conclude benign.

# Pcap \#45

Looks like someone is trying to gather information about whether a particular web server at 172.16.17.136 is only accessible through a certain port. The source port number is incremented each time as seen, and each packet is pretty much almost exactly a second apart. This is malicious.

# Pcap \#46

Just a bunch of ARP requests for the IP 172.16.17.138. Nothing malicious here.

# Pcap \#47

Looks like a continuation from pcap 46, except this time there are some DNS requests as well. Again, nothing malicious.

# Pcap \#48

Same as pcap 44 except the client and server are backwards now? It seems like the server is asking the client for the details.html page. Might be a bug with wireshark, but again there's nothing malicious here.

# Pcap \#49

There doesn't seem to be anything malicious here. Just looks like someone checking their mail at www.throwawaymail.com. Although there are a lot of dropped packets and a lot of re-transmissions, I don't see anything malicious here.

# Pcap \#50

There is some ARP traffic at the beginning, but then there is a very consistent pattern of ICMP packets followed by DNS packets. The ICMP packets seem to have a payload of "!\"#$%&'()\*+,-./01234567" which looks like someone is trying to see if weird characters in an ICMP payload will crash the other machine. I will go with malicious simply because of the crafted packets.

# Pcap \#51

Standard DNS traffic. Benign.

# Pcap \#52

Benign. It seems like some user making WHOIS queries to a server.

# Pcap \#53

Looks benign. Just some DHCP requests. 

# Pcap \#54

Unsure, but looks like someone just running a speedtest. There are some WEIRD requests on port 8080, but again, nothing I would classify as malicious.

# Pcap \#55

Looks like someone with terrible internet connection. There are lots of re-transmissions, but nothing malicious.

# Pcap \#56

Some DNS requests for some debian package repositories. Seems like someone trying to update their Ubuntu machine. Benign.

# Pcap \#57

Malicious. Looks like someone trying to see if sending the string "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^\_" to the UDP ports between 33434-33468 will affect the remote server in any way. Could be trying to find port knocking services or just seeing if the remote machine crashes at any time.

# Pcap \#58

Malicious. Someone is sending SYN packets to port 3000 over and over again. Mihai seems to have put the message "Checking the payload is a good idea" into the payload.

# Pcap \#59

Malicious. Nikto scan.

# Pcap \#60

Someone connects to FTP anonymously and tries to list files, as well as tries to store a file there. Very suspicious.

There are SYN packets sent to port 139, 256, 554, and 3389, with no response. It seems like a scan trying to find ports for netbios, checkpoint firewall, RTSP, and RDP. So I will go with malicious.