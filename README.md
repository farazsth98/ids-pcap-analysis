# Workshop \#1

**Q1.** IPv6 obviously has a ton more IP addresses than IPv4. This allows every single machine in the world to be assigned a unique IPv6 address, which isn't possible with IPv4. This means that NAT isn't required anymore, which makes network scanning almost impossible using tools that are designed for IPv4 simply because theres so many addresses and no actual subnetting. An internal network can have any number of IP addresses from any range, thus there is no rule that the network would follow.

**Q2** One way would be to introduce something at the hardware level that identifies certain machines as being part of a subnet, but it isn't being done widely and is much harder to implement. It is also more restrictive to change.

**Q3** Private network addresses are addresses that are particularly reserved for private networks. These include the 192.168.0.0/24 block, the 172.16.0.0/16 block, and the 10.0.0.0/8 block. Private network addresses increase security by preventing traces from being performed easily due to NAT translating between public and private IP addresses at network boundaries.

**Q4.** DNS cache poisoning is where an attacker can spoof (act like) a DNS server and make specific victim machine use this fake DNS server to perform DNS resolution requests. The attacker can then send back any IP address as a response, which would allow the attacker to perform stuff like phishing attacks very easily. Its overall aim is to get the user to think they are going to a legitimate website when they are actually not.

**Q5.** [See this](http://www.omnisecu.com/tcpip/ipv6/comparison-between-ipv4-header-and-ipv6-header.php).

**Q6.** A TCP session can be closed in two ways. First is using the FIN flag, where one side of the connection will send a packet with the FIN flag set to signify that they are ready to close. The other side will then send a FIN ACK packet, at which point the first side will wait for another FIN flag before closing the connection. This lets the second side finish off any processing they need to do. They will finally send a FIN packet, which the first side follows with a FIN ACK packet, thus closing the connection.

The second way to terminate the connection is with a RST packet. This will terminate the connection abruptly and immediately.

**Q7**. The checksum is calculated based on the content that is within the packet. The checksum is unique for each content, meaning that if an attacker changes the content stored within the packets, they'll also need to recalculate the checksum. This is very easily done these days, so it's safe to say that it should only be used for error checking and network fault checking circumstances.

**Q8**. The statement is incorrect. Multicasting is where one sender sends packets to multiple receivers. Having to constantly establish connections before being able to send the packets means that there will be a lot of delay.

**Q9**. UDP, simply because video streaming requires a lot of data transfer, where if some data gets dropped, nothing really adverse happens. With TCP though, there would be multiple connections that would need to be established, and the data would have to be sent in (relatively) smaller chunks (since TCP has a limit to how much data you can send per connection). Thus UDP is more suited.

**Q10.** Net unreachable, Host unreachable, Protocol Unreachable, Port Unreachable.

# Workshop \#2

**Q1**. A false negative is the most dangerous. A false negative is when there is a threat, but based on the data from the IDS/IPS, you're forced to determine that there is no threat. The attacker can then exfiltrate as much data as they want and cause a lot of damage without you ever realizing it.

**Q2**. Using OS fingerprinting, you can configure the IDS to ignore certain attacks. A good example is when your entire network consists of only linux servers. In that case, you can just configure the IDS to ignore all forms of attacks that target windows machines specifically (Eternal Blue, BlueKeep, etc). This not only saves time (no need to try to figure out how to deal with false positives when setting up the IDS to detect those attacks), but also saves resources, since the IDS can just ignore such cases and focus its resources on more important things.

**Q3**. You would require some form of a honeypot to detect insider attacks without an anomaly based IDS. For example, set up a fake database with real looking (but fake) customer credentials. Any access to that database should then be logged by the database, as no legitimate user should ever try to access that database for any reason whatsoever. 

**Q4**. There are two reasons. One is that such analysis requires a lot of resources. An IDS/IPS only has so many resources it can use, therefore performing deep analysis on every packet would essentially cause the IDS/IPS to DoS itself. The second reason is that applications and protocols never follow any strict guidelines. Sure, there are publically available RFCs, but applications and protocols regularly deviate from them, and also constantly update themselves over time. The IDS/IPS rules would need to be specific not just to each protocol/application, but the rules would have to be updated quite frequently as the applications/protocols change.

**Q5**. Shallow packet analysis is when only a packet's headers are analysed. The payload is never analysed. Three examples of malicious activity that can be detected are a) when a packet comes in from an external network (i.e it is at the gateway) with an internal IP, obviously crafted, b) when an nmap scan to look for open ports is going on, you can check the destination ports of all incoming packets, sort them, and see that they're in a sequential order which is exactly what an nmap scan would look like, and c) when an attack is going on where the attacker sends TCP packets with random flags set, such as one packet with SYN, ACK, FIN, PSH, then another packet with URG, FIN, ACK, PSH, etc. Checking the header would also show that these flags are set.

**Q6**. Honeypots are fake machines/files/databases/etc that are set up on a network. Honeypots can contain anything from a known vulnerable operating system to a database full of fake customer records (including customer credit cards, passwords, etc). Honeypots are specifically used to detect insider attacks and/or when a network has been compromised but the network IDS/IPS has missed the intrusion. An IDS/IPS can be set up to specifically detect any attempt to attack/access a honeypot, and log them / block the IPs / etc. For example, you can set up a text document on an unsecured machine on the network, called "EMPLOYEE_PASSWORDS.txt", and set up an IDS to log any access to this file.

**Q7**. False positives waste a lot of time. System administrators prefer to only go through valid IDS/IPS alerts, however, if there are a lot of false positives, they might just give up on actually checking every single alert every day due to it becoming a waste of time to do so (too many false positives). This is a major problem as it defeats the purpose of using an IDS/IPS. 

**Q8**. Data normalization is where anomaly based IDS/IPSs will build up a profile of what normal data looks like over time. For example, over the course of a month, an organization might only get a certain amount of traffic on ports 22, 80, 443, and 445. Once this profile has been established, should a malicious actor decide to (for example) do an nmap scan for open ports, the anomaly based IDS/IPS will immediately pick it up as an anomaly as it deviates from the "normal" profile. An attacker can circumvent this by very slowly over time scanning one port at a time each day, or every 2 days. This way, the IDS/IPS will not immediately detect it as an anomaly, and it will also update its "normal" profile with the one or two port scans everyday (i.e it might start thinking that a single port scan every day is a normal occurrence). This allows the attacker to circumvent data normalization and perform the port scans.

**Q9**. In order to reduce the amount of traffic that passes through an IDS/IPS, a firewall is deployed usually before the traffic ever reaches the IDS/IPS. That way, the firewall can just drop all traffic that is destined for random ports that the network never uses for any legitimate purpose (such as port 4444, for example). This way, the IDS/IPS has to deal with less traffic, allowing it to do a better job.

# Workshop \#4

**Q1.** a) it can start blacklisting IPs / hardening firewall rules / etc to slow down / stop the attack from happening. It can also detect data exfiltration and block IPs that have been connected for a long time. It can also do that based on the amount of data being exfiltrated. b) It can also use signatures to detect known attacks and change the attack payloads on the fly to make them harmless (for example changing all the attack payload into \x90 bytes which are NOPs).

**Q2.** A signature based IDS works by having a database of signatures for known types of attacks / scans / etc. It will use this information to detect when any of these attacks take place. The problem is that since this type of IDS only uses signatures, they don't actually "understand" all the various protocols that a connection might use, thus it can't detect attacks that it doesn't already have signatures saved for.

**Q3.** a) A known attack such as Eternal Blue. b) Scan emails and use signatures to detect known attacks over email c) You can look for error codes such as when someone turns off auditing in Windows, there is a specific code that gets put into the logs. d) Check for root logins through stuff like telnet, ftp, ssh, etc.

**Q4.** A slow slicing attack happens over a very long period of time. Assuming that this question is talking about anomaly based IDSes, these IDSes depend on attacks being anomalies. If an attack is done over a very long period of time, the anomalies that the attack might produce start to look like normal traffic to the IDS, thus the IDS will never be able to detect such an attack.

**Q5.** NBIDSes (Network Based Intrusion Detection Systems) have huge amounts of traffic to sift through since a network will more than likely have a huge number of machines thus a huge amount of traffic. With OS fingerprinting, the NBIDS can only look for attacks that matter to it. For example, if a network only has Linux machines, then it is useless to detect attacks like BlueKeep or EternalBlue, therefore the IDS will just let them pass through, since they are practically harmless. This reduces the load on the NBIDS in general, thus its becoming a very common technique.

**Q6.** With TCP port 4444 open, I would expect to see a meterpreter shell in the trace activity because that is the default port that metasploit listens on to create meterpreter connections.

**Q7.** Protocol/application analysis requires a lot of resources as the IDS has to do a deep packet scan and also be able to detect attacks / anomalies. Another problem is that protocols and applications are not standard. They are defined by RFCs meaning that some protocols and applications can have some different implementations in the way certain things are handled. When you set up rules for the IDS, it depends on these standards being followed, but a lot of applications won't, thus it will be a key problem. The last problem is that protocols and applications always change over time to defend against new attacks, to patch stuff, etc. When these happen, it becomes a challenge. All rules that pertain to that protocol/application needs to be recreated and changed.

**Q8.** The four types of events are true positive, true negative, false positive, and false negative events. The most dangerous would be a false negative, where in reality there is an attack going on, but the IDS says that there are no attacks going on. This will let the attack fly by completely undetected.

# Workshop \#6

**Q1.** 1) Blinding attacks: send as many packets as possible so the sensors don't know where to look. You can sneak malicious packets through in amidst blinding attacks. 2) Extremely slow and controlled attacks. Sensors will most likely detect anomalies, so very slow attacks can bypass sensors as it doesn't bypass the sensor's anomaly threshold. 3) By manipulating the TTLs in the packets so that some packets get dropped right at the sensor and others go through. Breaking up packets like that will cause them to more likely get past sensors since sensors try to detect whole attacks.

**Q2.** Since packets start getting dropped, the system will start slowing down due to missing packets. This can cause lots of problems, especially if critical packets start being dropped.

**Q3.** NIPS can be deployed right at the gateway, or in between two internal subnets. When deployed at the gateway, it has the benefit of having every single packet from the outside pass through it. The disadvantage there is that it could be too many packets for the NIPS to handle, thus it ends up dropping packets when overloaded. The benefit of having it in between any two internal subnets is that it prevents malicious traffic from being able to get out of one subnet (i.e only that one subnet will be owned by the attacker). The other benefit of that is that the NIPS won't have literally every single packet on the network passing through it, thus letting it do its job more effectively.

**Q4.** Multi-resolution filtering is where the NIPS will have multiple levels of checking for malicious activity, but it will only go into the deeper levels if it detects malicious activity in the more shallower levels. For example, if a packet comes into the network, the NIPS (with multi-resolution filtering enabled) will first only do a shallow packet analysis and check the headers of the packet. If it sees something malicious in the headers, only then does it perform a deep packet analysis to figure out whether the packet is truly malicious or not.

**Q5.** They should just drop them immediately, because by definition a packet that comes through the gateway with an internal IP address has been maliciously crafted.

**Q6.** The NIPS would definitely have a smaller database of attack signatures, as they need to be fast. A bigger database of attack signatures means it takes longer to search through all of the signatures, and an NIPS must be quick to prevent the attack, so to reduce latency this is what happens. IDSs generally have 4-5x larger databases of signatures.

**Q7.** HIDS generally use either file system based analysis or process based analysis. You either analyse the filesystem logs to find when people try to access files that they shouldn't try to access, or you analyze processes to find any rogue processes / processes that should not be there. For me personally, I'd try to use a process based analysis technique, as I believe that a host based IDS should be there to find if the host has been compromised by a virus or malware. Process based analysis will catch that. I believe that in a network, every "host" will be owned by some user (unless its a server or a DC), therefore the hosts themselves won't have any files on them that the users shouldn't have access to. An NIDS should be used to detect things like that.

**Q8.** Most expensive part is definitely the part where you have to spend time setting up the IDS/IPS rules. It takes a long time to tweak them to be perfect and reduce the amount of false alarms that they cause, and it can get very tedious so it takes a lot of money and time to do it.

**Q9.** The anomaly based IPSs only work if the attack creates anomalies that are enough to go above the threshold that is set for that IPS. If the attacker slows down their attack considerably, it is likely that the attack will pass right under the radar of the IPS. This is the main criticism against anomaly based IPSs.

# Workshop \#7

**Q1.** It is a piece of code that only runs on specific conditions such as when a malicious file might be transferred or if maybe someone tries to authenticate as root on ftp/ssh. What the shim will do then is it will block the activity from taking place. It is mostly used with intrusion prevention systems.

**Q2.** One other way would be to monitor system and application logs to see if any malicious activity has taken place such as malicious file access or etc. The other way would be to do integrity checking on the file by using checksums file known file signatures.

**Q3.** You can overwrite parts of a packet / break up a packet change each fragment's TTL so that some get stopped at the IDS, whereas others will pass through the IDS and get reconstructed further down, thus bypassing the IDS.

**Q4.** Stands for Tribal Flood Network. It essentially means a botnet that you can control from a CnC (Command and Control) center. This can be used to launch ddos attacks on any host very easily.

**Q5.** The first method would be to have built in redundancy, such that the same "server" has multiple public facing IP addresses. If one of them get ddossed, the others won't be affected and will continue functioning. The second way would be to outsource the job.

**Q6.** The heap not only contains allocated chunks, but it generally also contains metadata for these chunks. A heap based buffer overflow can be used to overwrite this metadata with user defined data. If done right, specially crafted user defined data can overwrite the heap metadata in such a way to allow for arbitrary code execution.

**Q7.** A honeypot admin account is one that is setup and possibly visible to anyone that has access to the network, but one that no one should even attempt to access. Any attempts to access the honeypot admin account will be logged and can be viewed by an admin to determine if something malicious is going on, or if its just some curious sysadmin.

**Q8.** First would be to use modern encryption such as WPA2, and possibly use Radius for authentication instead of using preshared keys. Second would be to make sure that the signal strength is modified to be as low as possible whilst covering the entire building / premises. This prevents other people from outside the premises from being able to access it. The third is to do regular sweeps of the network for rogue APs.

# Workshop \#8

**Q1.** 1. A log retention policy should be put in place. Information regarding incidents/alerts can originate from various places, such as firewalls, IDS/IPSs, and application logs. A policy should be set up to determine how long log data should be maintained for, as older log entries may show reconnaissance activity or previous instances of similar attacks after an incident. 2. Users should be made aware of policies and procedures regarding appropriate use of networks, systems, and applications. They should be trained on password policies, and lessons should be learned from previous incidents so that the users can see how their actions affect the organization as a whole. 3. A profile of "normal network behavior" should be created. Examples are monitoring network bandwidth usage, as well as CPU usage of critical machines so that in the event something is compromised, the anomalous behavior can be used to detect the compromise and stop it before it becomes too much of a problem. 4. A backup of all data should be kept, and updated regularly, so that in the case of an attack, the organization can go back to its most recent backup and restart. 

**Q2.** 1. Compile information about the incident: details about what systems have been compromised, whether the attack is contained within a subnet or if its more widespread, etc. 2. Contain the incident immediately. After compiling all the information, the next immediate task should be to take all of the compromised machines off the network to prevent the attack from spreading and compromising other uncompromised machines. 3. Interview any relevant personnel such as sysadmins, managers, end users, etc to figure out exactly how or why the attacker may have performed the attack. Did the users of the affected machines download any malware? Ask questions like those. 4. Create a backup of all affected machines. This is necessary before wiping, re-imaging, or interacting with any of the affected machines in general, as this allows you to capture the affected systems just as they were during the incident and thereby preserving evidence in the event that the incident resulted in a criminal act or had any legal implications. 

**Q3.** 1. Make sure every application is patched. 2. Make sure privileges are set correctly. 3. Implement strong application whitelisting. 4. Make sure every OS is patched appropriately.

**Q4.** You cannot trust the compromised system, which is why you should use read-only media to use your own tools to perform the incident handling.

**Q5.** Answers taken from [here](http://media.techtarget.com/searchNetworking/Downloads/IncidentResponseChapter2.pdf). 1. Initial live response: This involves obtaining only the volatile data from a target or victim system. An initial live response is usually performed when you have decided to conduct a forensic duplication of the media. 2. In-depth live response: This goes beyond merely obtaining volatile data. This obtains additional information from the target / victim system to determine a valid response strategy. Non-volatile information such as log files are collected to help understand the nature of the incident. 3. Full live response: This is a full investigation on a live system. It is the opposite of the initial live response, as it collects all data for the investigation from a system that is powered on, whereas a forensic duplication (for example, in an initial live response) would require the system to be powered off.

**Q6.** You have to rely on the cloud provider to give you the information, which might be an extra feature that they sell. If you however set your own incident handling system with IDSs and IPSs and logging facilities, then you can use most of the same techniques still to perform your own incident handling.

# Workshop \#9

**Q1.** Generak's answer: No, because systems these days are far more distributed and have a lot more data stored than back then, which means that it is harder to obtain all the data in a reasonable amount of time. An organization might have cloud servers in various locations worldwide (for example), and collecting logs from all of them in a reasonable time might be difficult.

**Q2.** Application log files (any application specific logs), security log files (anything related to logins, etc), and system log files (anything related to operating system specific logs such as kernel crashes, driver crashes, etc).

**Q3.** You can view event logs on a Windows system by opening Event Viewer. It is an application that is pre-installed on every Windows system.

**Q4.** By default, the security event logging is not configured well enough. As an example, there is no default logging of successful logins which could indicate that an account has been compromised (if a login is detected at, say, 3:00am).

**Q5.** I would check the list of services that run on startup to see if there is any suspicious service that runs on startup. It is likely that the attacker inserted a backdoor that way to gain access whenever he wants to. A service that runs on startup and tries to reach out to the hacker machine every 20 minutes is an easy way to get a reverse shell whenever the attacker wants.

**Q6.** First and foremost, a forensic copy of the entire system must be made. Then, the first type of evidence that should be collected are logs. This allows for a valid response strategy to be built.

**Q7.** The file is completely removed from the system, however, the bytes that it occupied on the hard drive are not zeroed out. Specialized forensics tools can be used to recover the data.

**Q8.** On UNIX systems, there are generally a ton more processes running compared to a Windows machine. Couple that with the fact that a rogue process can rename itself, embed itself into another process, etc, and the time taken to find a rogue process is exponentially greater on a UNIX system compared to a Windows system.