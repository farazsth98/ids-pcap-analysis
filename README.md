# Workshop 1

Q1. IPv6 obviously has a ton more IP addresses than IPv4. This allows every single machine in the world to be assigned a unique IPv6 address, which isn't possible with IPv4. This means that NAT isn't required anymore, which makes network scanning almost impossible using tools that are designed for IPv4 simply because theres so many addresses and no actual subnetting. An internal network can have any number of IP addresses from any range, thus there is no rule that the network would follow.

Q2. One way would be to introduce something at the hardware level, but it isn't being done widely.

Q3. Private network addresses are addresses that are particularly reserved for private networks. These include the 192.168.0.0/24 block, the 172.16.0.0/16 block, and the 10.0.0.0/8 block. Private network addresses increase security by preventing traces from being performed easily due to NAT translating between public and private IP addresses at network boundaries.

Q4. DNS cache poisoning is where an attacker can spoof (act like) a DNS server and make specific victim machine use this fake DNS server to perform DNS resolution requests. The attacker can then send back any IP address as a response, which would allow the attacker to perform stuff like phishing attacks very easily. Its overall aim is to get the user to think they are going to a legitimate website when they are actually not.

Q5. 

Q6. A TCP session can be closed in two ways. First is using the FIN flag, where one side of the connection will send a packet with the FIN flag set to signify that they are ready to close. The other side will then send a FIN ACK packet, at which point the first side will wait for another FIN flag before closing the connection. This lets the second side finish off any processing they need to do. They will finally send a FIN packet, which the first side follows with a FIN ACK packet, thus closing the connection.

The second way to terminate the connection is with a RST packet. This will terminate the connection abruptly and immediately.

Q7. The checksum is calculated based on the content that is within the packet. The checksum is unique for each content, meaning that if an attacker changes the content stored within the packets, they'll also need to recalculate the checksum. This is very easily done these days, so it's safe to say that it should only be used for error checking and network fault checking circumstances. 

Q8. The statement is incorrect. Multicasting is where one sender sends packets to multiple receivers. Having to constantly establish connections before being able to send the packets means that there will be a lot of delay. 

Q9. UDP, simply because video streaming requires a lot of data transfer, where if some data gets dropped, nothing really adverse happens. With TCP though, there would be multiple connections that would need to be established, and the data would have to be sent in (relatively) smaller chunks (since TCP has a limit to how much data you can send per connection). Thus UDP is more suited.

Q10. Net unreachable, Host unreachable, Protocol Unreachable, Port Unreachable.