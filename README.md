stealth scan detection daemon
=====================

compile pdefdev.c and scan_detector.c, then use the bash wrapper program scandd.

usage: ./scandd [start | stop | status | clear | png]

start - run the scan_detector daemon

stop - kill the scan_detector daemon process

status - print the scan detection daemon's logs

clear - erase the scan detection daemon's logs

png - draw a graph of captured scans
