# Pcap \#31

Benign.

* Mostly HTTP traffic where the user (192.168.56.105) connects to the website at 192.168.56.106 and gets the default APACHE webpage. It looks like this is on a local network due to the IPs.

* The user also seems to try to connect to SSH twice but finds that the port is closed.

* Nothing unusual about it.

# Pcap \#32

Looks benign. Someone connects to the website at 192.168.56.107 and gets the home page, which just says "The flag is Legio Panonica 87". The User Agent shows that they are using Iceweasel though, which is the default version of Firefox that comes with Kali Linux, so maybe this is someone solving a challenge of some sort where they get given a flag to show that they solved it correctly.

The user also tries to connect to port 443 later to see if there is an HTTPS version of the website running as well.

# Pcap \#33

Malicious.

* Someone tries to login as root:root, very suspicoius

* Then they try to login as Dacia:Dacia

* Then they open another connection and give up.

* All of this is done manually.

# Pcap \#34

Non-malicious. Someone logs into their MySQL server and tests it out by creating an example table, inserting stuff into it, deleting stuff from it, then dropping the table.

# Pcap \#35

Malicious. Seems like someone connects to another machine and performs an `ls -la` followed by `cd`ing into `selinux` and doing another `ls -la`. This interaction happens over port 4440, thus it is most likely a reverse shell.

# Pcap \#36

Malicious. Attacker is at 192.168.56.105

* The attacker first starts off by doing an nmap scan. He finds some ports open, then he switches his attention to the web server at port 80 and starts sending very weird TCP packets to it with stuff like the SYN, ECN, CWR, and Reserved flags set, as well as the FIN, SYN, PSH, and URG flags set.

* He performs recon on the web app by looking for robots.txt and doesn't find it.

# Pcap \#37

Malicious. Attacker is at 192.168.56.105

* The attacker seems like he's testing a web application. Multiple times he sends a SYN packet, the web server responds with a SYN ACK, and the attacker responds with an RST packet.

* He then establishes a connection and starts sending FIN ACK packets, followed by a bunch more SYN and ACK packets. He then drops the connection using an RST packet, and does the SYN -> SYN ACK -> RST thing a couple times.

* He then pings the web server, presumably to check if he's crashed it. The webserver shows as still up.

* He then connects to it and tries to look for a /.git folder, followed by a /robots.txt folder, followed by some OPTIONS and GET requests, until finally closing the connection cleanly.

# Pcap \#38

Benign. Normal NTP traffic.

# Pcap \#39

Looks malicious, the attacker is performing recon on the SMB share. First on the IPC$ share then the USER share, he tries to look for files such as `\desktop.ini` and other files.

# Pcap \#40

Malicious. The attacker at IP 192.168.56.105 is just sending garbage UDP and ICMP packets to 192.168.56.106 to see how it would react.
