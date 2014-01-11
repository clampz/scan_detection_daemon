nmap scan detection daemon
=====================

The scan detection daemon sniffs packets in the background using the packet
capture library (pcap), filtering out packets with certain tcp flags (each corresponding to a default nmap scan) on, pointed
at the host computer and logs information to files in ```/var/logs/```.

***dependancies***: Neato (part of the Graphviz pkg.)

To run the stealth scan detection daemon, compile pdefdev.c and scan_detector.c, then use the bash wrapper program scandd.

***Usage***: ./scandd [start | stop | status | clear | png]

start - run the scan_detector

stop - kill the scan_detector process

status - print the scan detector's logs

clear - erase the scan detector's logs

png - draw a graph of captured scans
