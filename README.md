NMAP scan detection daemon
=====================

The scan detection daemon sniffs packets using a packet capture library (pcap), filtering out certain (60 byte packet len and < 24 byte tcp header len) packets (based on default NMAP scans, UDP or TCP [SYN, FIN, NULL, XMAS, MAMN]), pointed at the host (or a given) computer and logs information to files in ```/var/log/```.

***Dependancies***: Neato (part of the Graphviz pkg) and pcap.

***Usage***: ```scandd [start [SCAN_TYPE=color] | startwith IP_ADDR [SCAN_TYPE=color] | stop | status | clear | png]```

***Example***: ```scandd startwith 192.168.0.20 "SYN=red" "MAMN=lawngreen"```

***Install***: ```make; sudo make install```

***NOTE***: because pcap requires root privs, running scandd also requires the user to be root. To become root user, use the following command: ```su root```

start - run the scan_detector

stop - kill the scan_detector process

status - print the scan detector's logs

clear - erase the scan detector's logs

png - draw a graph of captured scans

