# Pcap \#11

Nothing malicious about this.

* We see someone authenticating to an SMTP server and setting a bunch of variables before quitting.

* There is only this conversation between the client at 192.168.20.70 and the server at 74.125.131.27




# Pcap \#12

There are 2100 packets transferred back and forth in 1.888728 seconds, which means this is interaction has definitely been automated.

* As for whether it is malicious or not, my answer would be that it is, simply because 2100 packets being transferred in less than 2 seconds seems like someone is automatically gathering information / attempting to DOS / attempting to brute force credentials

* However we cannot say what they're doing for sure since the interaction is encrypted.

* Unsure about this




# Pcap \#13

There is a single IPv4 packet sent by 192.1.2.9 to 192.1.2.1 with checksum validation disabled.

* Unsure about this




# Pcap \#14

My first impression is that the IP addresses are very weird here.. We have 1.1.1.2 as the client and 1.1.1.2 as the supposed DNS server.

* A TCP connection is established, and the client makes a DNS query for `etas.com`.

* The client is sent a response stating `training2003p` and `hostmaster` which I assume are subdomains?

* Unsure about this




# Pcap \#15

Nothing malicious about this.

* The client 192.168.1.140 connects to a website located at 174.143.213.184 and sends a GET request for a `logo.png` file.

* The `logo.png` is just an image of the PacketLife.net logo.




# Pcap \#17

Kind of suspicious but nothing malicious about it stands out.

* A client 192.168.1.140 connects to a server at 192.168.1.194 using telnet.

* User: `test` and Password: `capture`

* Once in, they just run `uname -a` to view the version of the OS. Seems like a sys-admin or someone from IT who just telnetted into a machine on the local network to check what version of Linux it is running.

* The one weird thing is that the `DISPLAY` environment variable seems to be set to `Sandbox`. Unsure what that means.




# Pcap \#18

Definitely malicious.

* The attacker 172.16.16.128 initially establishes and terminates 6 connections, presumably to gather information about SMB shares since
