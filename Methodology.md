1. Check Protocol Hierarchy to get an idea of what this pcap file is about

2. Check Conversations, note the number of IP addresses talking to each other, number of MAC addresses talking to each other, amount of time taken during conversations etc. Remember to sort by port numbers, window sizes, packet sizes, etc.

3. Follow TCP streams / UDP streams, see what the conversations actually look like. Remember to sort by different columns and see if anything pops out at you.

4. Check to make sure TCP flags are set as normal.

5. Check for automated scans / attacks (lots of packets in a short amount of time)

6. If all else fails, pick out a couple packets and check them manually to make sure checksums.

7. Remember to check for downloadable files.
