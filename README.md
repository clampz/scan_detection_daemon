NMAP scan detection daemon
=====================

The scan detection daemon sniffs packets using a packet capture library (pcap), filtering out certain (60 byte packet len and < 24 byte tcp header len) packets (based on default NMAP scans, UDP or TCP [SYN, FIN, NULL, XMAS, MAMN]), pointed at the host (or a given) computer and logs information to files in ```/var/log/```.

***Dependancies***: neato (part of the [Graphviz](https://packages.debian.org/wheezy/libgraphviz-dev) pkg) and [pcap](https://packages.debian.org/squeeze/libpcap-dev).

***Usage***: ```scandd [start [SCAN_TYPE=color] | startwith IP [SCAN_TYPE=color] | stop | status | clear | png]```

***Example***: ```scandd startwith 192.168.0.20 "SYN=red" "MAMN=lawngreen"``` starts the scan detection daemon with a given ip address and colors the respective given scan types.

***Install***: (Debian Linux) ```make; sudo make install```

***NOTE***: because pcap requires root privs, running scandd also requires the user to be root. To become root user, use the following command: ```su root```

start - run the scan_detector

startwith - run the scan_detector with an IP address specified

stop - kill the scan_detector process

status - print the scan detector's logs

clear - erase the scan detector's logs

png - draw an undirected graph of captured scans

An example graph:

![alt text](https://raw.githubusercontent.com/clampz/scan_detection_daemon/master/ex/example_scan_detect.png "Example NMAP Scan 1")

