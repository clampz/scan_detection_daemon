
INSTALLDIR=/usr/sbin

all: compile

compile:
	gcc src/pdefdev.c -o pdefdev -lpcap
	gcc src/scan_detector.c -o scan_detector -lpcap

install:
	cp pdefdev $(INSTALLDIR)
	cp scan_detector $(INSTALLDIR)
	cp src/scandd $(INSTALLDIR)

uninstall:
	rm $(INSTALLDIR)/pdefdev $(INSTALLDIR)/scan_detector $(INSTALLDIR)/scandd
	rm /var/log/scan_detectd.log /var/log/scan_detectd_graph.log

clean:
	rm ./pdefdev
	rm ./scan_detector

