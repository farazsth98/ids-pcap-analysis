# Workshop 1

**Q1.** IPv6 obviously has a ton more IP addresses than IPv4. This allows every single machine in the world to be assigned a unique IPv6 address, which isn't possible with IPv4. This means that NAT isn't required anymore, which makes network scanning almost impossible using tools that are designed for IPv4 simply because theres so many addresses and no actual subnetting. An internal network can have any number of IP addresses from any range, thus there is no rule that the network would follow.

**Q2** One way would be to introduce something at the hardware level, but it isn't being done widely.

**Q3** Private network addresses are addresses that are particularly reserved for private networks. These include the 192.168.0.0/24 block, the 172.16.0.0/16 block, and the 10.0.0.0/8 block. Private network addresses increase security by preventing traces from being performed easily due to NAT translating between public and private IP addresses at network boundaries.

**Q4.** DNS cache poisoning is where an attacker can spoof (act like) a DNS server and make specific victim machine use this fake DNS server to perform DNS resolution requests. The attacker can then send back any IP address as a response, which would allow the attacker to perform stuff like phishing attacks very easily. Its overall aim is to get the user to think they are going to a legitimate website when they are actually not.

**Q5.**

**Q6.** A TCP session can be closed in two ways. First is using the FIN flag, where one side of the connection will send a packet with the FIN flag set to signify that they are ready to close. The other side will then send a FIN ACK packet, at which point the first side will wait for another FIN flag before closing the connection. This lets the second side finish off any processing they need to do. They will finally send a FIN packet, which the first side follows with a FIN ACK packet, thus closing the connection.

The second way to terminate the connection is with a RST packet. This will terminate the connection abruptly and immediately.

**Q7**. The checksum is calculated based on the content that is within the packet. The checksum is unique for each content, meaning that if an attacker changes the content stored within the packets, they'll also need to recalculate the checksum. This is very easily done these days, so it's safe to say that it should only be used for error checking and network fault checking circumstances.

**Q8**. The statement is incorrect. Multicasting is where one sender sends packets to multiple receivers. Having to constantly establish connections before being able to send the packets means that there will be a lot of delay.

**Q9**. UDP, simply because video streaming requires a lot of data transfer, where if some data gets dropped, nothing really adverse happens. With TCP though, there would be multiple connections that would need to be established, and the data would have to be sent in (relatively) smaller chunks (since TCP has a limit to how much data you can send per connection). Thus UDP is more suited.

**Q10.** Net unreachable, Host unreachable, Protocol Unreachable, Port Unreachable.

# Workshop \#4

**Q1.** a) it can start blacklisting IPs / hardening firewall rules / etc to slow down / stop the attack from happening. It can also detect data exfiltration and block IPs that have been connected for a long time. It can also do that based on the amount of data being exfiltrated. b) It can also use signatures to detect known attacks and change the attack payloads on the fly to make them harmless (for example changing all the attack payload into \x90 bytes which are NOPs).

**Q2.** A signature based IDS works by having a database of signatures for known types of attacks / scans / etc. It will use this information to detect when any of these attacks take place. The problem is that since this type of IDS only uses signatures, they don't actually "understand" all the various protocols that a connection might use, thus it can't detect attacks that it doesn't already have signatures saved for.

**Q3.** a) A known attack such as Eternal Blue. b) Scan emails and use signatures to detect known attacks over email c) You can look for error codes such as when someone turns of auditing in Windows, there is a specific code that gets put into the logs. d) Check for root logins through stuff like telnet, ftp, ssh, etc.

**Q4.** A slow slicing attack happens over a very long period of time. Assuming that this question is talking about anomaly based IDSes, these IDSes depend on attacks being anomalies. If an attack is done over a very long period of time, the anomalies that the attack might produce start to look like normal traffic to the IDS, thus the IDS will never be able to detect such an attack.

**Q5.** NDIDSes (Network Based Intrusion Detection Systems) have huge amounts of traffic to sift through since a network will more than likely have a huge number of machines thus a heg amount of traffic. With OS fingerprinting, the NBIDS can only look for attacks that matter to it. For example, if a network only has Linux machines, then it is useless to detect attacks like BlueKeep or EternalBlue, therefore the IDS will just let them pass through, since they are practically harmless. This reduces the load on the NBIDS in general, thus its becoming a very common technique.

**Q6.** With TCP port 4444 open, I would expect to see a meterpreter shell in the trace activity because that is the default port that metasploit listens on to create meterpreter connections.

**Q7.** Protocol/application analysis requires a lot of resources as the IDS has to do a deep packet scan and also be able to detect attacks / anomalies. Another problem is that protocols and applications are not standard. They are defined by RFCs meaning that some protocols and applications can have some different implementations in the way certain things are handled. When you set up rules for the IDS, it depends on these standards being followed, but a lot of applications won't, thus it will be a key problem. The last problem is that protocls and applications always change over time to defend against new attacks, to patch stuff, etc. When these happen, it becomes a challenge. All rules that pertain to that protocol/application needs to be recreated and changed.

**Q8.** The four types of events are true positive, true negative, false positive, and false negative events. The most dangerous would be a false negative, where in reality there is an attack going on, but the IDS says that there are no attacks going on. This will let the attack fly by completely undetected.
