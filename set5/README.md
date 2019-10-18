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

# Pcap \#50

There is some ARP traffic at the beginning, but then there is a very consistent pattern of ICMP packets followed by DNS packets. The ICMP packets seem to have a payload of "!\"#$%&'()\*+,-./01234567" which looks like someone is trying to see if weird characters in an ICMP payload will crash the other machine. I will go with malicious simply because of the crafted packets.

# Pcap \#51

Standard DNS traffic. Benign.

# Pcap \#52

Benign. It seems like some user making WHOIS queries to a server.

# Pcap \#53

Looks benign. Just some DHCP requests. 

# Pcap \#54

