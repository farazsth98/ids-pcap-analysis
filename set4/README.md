# Pcap \#31

Benign.

* Mostly HTTP traffic where the user (192.168.56.105) connects to the website at 192.168.56.106 and gets the default APACHE webpage. It looks like this is on a local network due to the IPs.

* The user also seems to try to connect to SSH twice but finds that the port is closed.

* Nothing unusual about it.

# Pcap \#32

Looks benign. Someone connects to the website at 192.168.56.107 and gets the home page, which just says "The flag is Legio Panonica 87". The User Agent shows that they are using Iceweasel though, which is the default version of Firefox that comes with Kali Linux, so maybe this is someone solving a challenge of some sort where they get given a flag to show that they solved it correctly.

The user also tries to connect to port 443 later to see if there is an HTTPS version of the website running as well. 
