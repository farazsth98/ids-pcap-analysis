# Pcap \#21

Malicious. ARP poisoning attack. Attacker is at Vmware_1d:b3:b1, at IP 192.168.47.171.

* Attacker starts off by doing recon by sending ARP requests for every IP in the 192.168.47.0/24 range.

* After finding out all live IPs, the attacker just sends out ARP messages to those IPs stating that all of those IPs will correspond to the attacker's MAC address.

* The result of this is that the attacker will be able to spoof himself as all of those IPs, so any packets destined for those IPs will then end up going to the attacker.

# Pcap \#22

Benign.

* We see someone trying to connect to a POP3 mail server, it seems like their default configuration had the wrong IP so the email client probably tries multiples IPs until it finds the right one.

* Then we see the user create a mail account and send some emails. Nothing malicious.

# Pcap \#23

This is definitely malicious. The attacker is at IP 192.168.47.171, and the target is at IP 192.168.47.134.

* The attacker initially makes an ARP request to find out where the target is located.

* Once he's got the target's MAC address, he starts doing an nmap scan with the -sN flag.

# Pcap \#24

Benign. It is just a person configuring a printer it looks like.

# Pcap \#25

This is benign.

* We see the majority of packets are Syslog packets, so there is some form of a logging server in this network that logs all messages.

* The machines are mostly windows machines as we see BROWSER announcements where it leaks out information about the machines being Windows Server 2003 or Windows Server 2003 R2.

* Other than that, we see some Syslog messages where someone successfully logs in as an admin into /index.php of some web server.

* Nothing malicious about this.

# Pcap \#26

Benign.

* We see someone try to connect using telnet but NTLM authentication fails. They then login using Administrator:napier as their credentials, do a directory listing, and exit.

# Pcap \#27

Malicious. The attacker is doing a UDP scan.

# Pcap \#28

Malicious. This is an Nmap scan with the FIN, PSH, and URG flags set probably to see how the target reacts to such packets.

# Pcap \#30

Benign. Simply someone checking their university email (not sure why its in plaintext but alright).
