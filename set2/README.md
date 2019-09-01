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




# Pcap \#16

Nothing malicious about this. Seems like someone just connects to a Cisco router and sets up routes to two other routers R0 and R1, then uses CDP (Cisco Discovery Protocol) to make sure they are connected, then pings one router from another to ensure that pings go through.




# Pcap \#17

Kind of suspicious but nothing malicious about it stands out.

* A client 192.168.1.140 connects to a server at 192.168.1.194 using telnet.

* User: `test` and Password: `capture`

* Once in, they just run `uname -a` to view the version of the OS. Seems like a sys-admin or someone from IT who just telnetted into a machine on the local network to check what version of Linux it is running.

* The one weird thing is that the `DISPLAY` environment variable seems to be set to `Sandbox`. Unsure what that means.




# Pcap \#18

Definitely malicious.

* The attacker 172.16.16.128 initially establishes and terminates 6 connections, presumably to gather information about SMB shares since every single connects to port 135 and terminates immediately.

* The attacker then pings the IP.

* The attacker then sends a huge UDP packet with a huge number of 'C's as the input to port 42283, presumably to check for a buffer overflow for some application that might be running on that port.

* The user then sends a series of TCP packets with multiple flags set to see how the server would respond (There's no reason to ever set the SYN, ECN, CWR, and Reserved flags at the same time).

* He seems to also play around with the window sizes of the TCP packets.

* After each series of these weird TCP packets, he tries the buffer overflow attack to see if it works again.

* Definitely a malicious pcap here.

# Pcap \#19




Looks malicious to me.

* The client at IP 192.168.100.206 goes to a website located at 192.168.100.202 and requests the `/info` with a GET request.

* The website immediately responds with a 302 and redirects the user to the `/info?rFfWELUjLJHpP` which contains a very obfuscated JS script embedded into the page.

* The user then apparently makes a GET request for `/infowTVeeGDYJWNfsrdrvXiYApnuPoCMjRrSZuKtbVgwuZCXwxKjtEclbPuJPPctcflhsttMRrSyxl.gif`. This is probably what the JS script made the user do, since immediately following it, we see a TCP connection between the website's IP and the client.

* In this connection, we see that the website has a reverse shell (cmd prompt) on the client's machine, and then does a `dir` command to list the files on the client's desktop. They find a `passwords.txt` file, and the client is probably pwned at this point.

# Pcap \#20

Cannot really classify it as malicious. It's just someone performing an nmap scan on the IP 64.13.134.52. The person doing the nmap scan has the IP 172.16.0.8
