stealth scan detection daemon
=====================

this stealth scan detection daemon sniffs packets in the background using the packet
capture library (<pcap/pcap.h>), filtering out packets with certain flags on, pointed
at the host computer and logs information to files in ```/var/logs/```.

compile pdefdev.c and scan_detector.c, then use the bash wrapper program scandd.

usage: ./scandd [start | stop | status | clear | png]

start - run the scan_detector daemon

stop - kill the scan_detector daemon process

status - print the scan detection daemon's logs

clear - erase the scan detection daemon's logs

png - draw a graph of captured scans
