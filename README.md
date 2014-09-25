NMAP scan detection daemon
=====================

The scan detection daemon sniffs packets using a packet capture library (pcap), filtering out certain (60 byte packet len and < 24 byte tcp header len) packets (based on default NMAP scans, UDP or TCP [SYN, FIN, NULL, XMAS, MAMN]), pointed at the host (or a given) computer and logs information to files in ```/var/log/```.

***NOTE***: The author of this software has not optimized this design for elimination of false positives. A test for false positives was preformed while the target host is running a web server hosting a simple blogging website, this program's filtering mechanisms were found to be sufficient during this test.

Additionally, starting the scan detector does require root user privileges as using libpcap also requires root.

***Dependancies***: neato (part of the [Graphviz](https://packages.debian.org/wheezy/libgraphviz-dev) pkg) and [pcap](https://packages.debian.org/squeeze/libpcap-dev).

***Usage***: ```scandd [start [SCAN_TYPE=color] | startwith IP [SCAN_TYPE=color] | stop | status | clear | png]```

***Example***: ```scandd startwith 10.0.1.70 "SYN=blue" "XMAS=lawngreen"``` starts the scan detection daemon with a given ip address and colors SYN scans as blue, and XMAS scans lawn green when you create a graph.

***Install***: (as root on [Debian - like] Linux distros) ```make; make install```

start - run the scan_detector

startwith - run the scan_detector with an IP address specified

stop - kill the scan_detector process

status - print the scan detector's logs

clear - erase the scan detector's logs

png - draw an undirected graph of captured scans

Example graph (after starting the scandd with the example command above, perhaps ```scandd png``` will output something like the following):

![alt text](https://raw.githubusercontent.com/clampz/scan_detection_daemon/master/ex/example_scan_detect.png "Example NMAP Scan 1")

