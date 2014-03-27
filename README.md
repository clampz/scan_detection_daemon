nmap scan detection daemon
=====================

The scan detection daemon sniffs packets in the background using the packet capture library (pcap), filtering out certain packets (based on default nmap scans, UDP or TCP [SYN, FIN, NULL, XMAS, MAMN]), pointed at the host computer and logs information to files in ```/var/log/```.

***Dependancies***: Neato (part of the Graphviz pkg) and pcap.

To run the scan detection daemon, compile pdefdev.c and scan_detector.c, then use the bash wrapper program scandd.

***Usage***: scandd [start | stop | status | clear | png]

Now, you can start scandd like so: scandd start "[SYN, FIN, NULL, XMAS, MAMN, UDP]=color", where the color can be color defined in your version of neato., For example ```scandd start "SYN=red"```

***Install***: ```make; sudo make install```

***NOTE***: because pcap requires root privs, running scandd also requires the user to be root. To become root user, use the following command: ```su root```

start - run the scan_detector

stop - kill the scan_detector process

status - print the scan detector's logs

clear - erase the scan detector's logs

png - draw a graph of captured scans
