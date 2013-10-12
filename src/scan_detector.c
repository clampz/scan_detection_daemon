/* scan_detector.c
 * written by: David Weinman
 * last update: 09/30/13
 * */

/* This file is licensed under The MIT License, see LICENSE for details. */

/* note: this code was influenced by Jon Erikson's
   'Hacking: The Art of Exploitation' */

/*

#include <pcap/pcap.h>

char *pcap_lookupdev(char *errbuf);
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
void pcap_close(pcap_t *p);

#include <arpa/inet.h>

char *inet_ntoa(struct in_addr in);

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int open(const char *pathname, int flags, mode_t mode);
int open(const char *pathname, int flags);
ssize_t write(int fd, const void *buf, size_t count);

#include <stdio.h>

int printf(const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);
int fprintf(FILE * restrict stream, const char * restrict format, ...);

*/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <signal.h>

#include "malloc_dump.h"
#include "net_structs.h"

#define LOGFILE "/var/logs/scandetectd.log" // log filename
#define GRAPHFILE "/var/logs/scandetectd_graph.log" // graph log filename

void handle_shutdown(int);
void scan_fatal(const char *, const char *);
void caught_packet(u_char*, const struct pcap_pkthdr*, const u_char*);
void alert_user(const struct eth_hdr*, const struct tcp_hdr*, const struct ip_hdr*, const char*, int);
int main(int, char **);
int isSYNPkt(const u_char*);
int isFINPkt(const u_char*);
int isXMASPkt(const u_char*);
int isNULLPkt(const u_char*);
int isUDPkt(const u_char*);

// host ip string pointer
char *host_ip;

// global log and graph file descriptors
int logfd, graphfd;

// This function is called when the process is killed 
void handle_shutdown(int signal) {

   timestamp(logfd);
   write(logfd, "Shutting down..\n", 16);
   close(logfd);
   close (graphfd);
   exit(0);

} // handle_shutdown

// an error function
void scan_fatal(const char *failed_in, const char *errbuf) {

        printf("Fatal Error in %s:", failed_in);
	fatal((char *) errbuf);
        exit(1);

} // scan_fatal

// main creates a listener and captures packets while looking 
// for SYN flags in the TCP header
int main(int argc, char ** argv) {

	int i = 0;
        struct pcap_pkthdr cap_header;
        const u_char *packet, *pkt_data;
        char errbuf[PCAP_ERRBUF_SIZE];
        char *device;
	pcap_t *pcap_handle;
	host_ip = argv[1];

	fdprintf(1, 40, "\nscandd running with ip: %s\n", argv[1]);

	logfd = open(LOGFILE, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);
	graphfd = open(GRAPHFILE, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);

        if (logfd == -1)
                fatal("opening log file");

   	timestamp(logfd);
	write(logfd, "Starting up..\n", 15);

	if (argc != 3) {printf("\nwrong # of args.\n\n"); exit(1);} 

	device = pcap_lookupdev(errbuf);

	if (device == NULL) {
		scan_fatal("pcap_lookupdev", errbuf);
	}

	if (daemon(0, 1) == -1) {
		fatal("forking to daemon process");
	}

	signal(SIGTERM, handle_shutdown);
	signal(SIGINT, handle_shutdown);

	pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);

	while (1) {

		if (i++ > 0) pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);

		pcap_loop(pcap_handle, atoi(argv[2]), caught_packet, NULL);
		pcap_close(pcap_handle);

	}

	return 0;

} // main

// this function is called by caught_packet when the conditions for scan detection are true.
// it prints scan detection information to the appropriate log files
void alert_user( const struct eth_hdr *eth_header, const struct tcp_hdr *tcp_header, 

	const struct ip_hdr *ip_header, const char *type, int fd) {

	char *src_addr, *dest_addr;
	int i;

	fdprintf(fd, 45, "\"[%s] src ip: %s\" ", type, inet_ntoa(ip_header->ip_src_addr));

	fdprintf(fd, 35, "-- \"dst ip: %s\";\n\n", inet_ntoa(ip_header->ip_dest_addr));

} // alert_user

// function that is called when a packet is caught, checks for a scan on host ip port, calls alert_user if detection comes up true.
void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {


	const struct eth_hdr *eth_header;
	const struct ip_hdr *ip_header;
	const struct tcp_hdr *tcp_header;
	eth_header = (const struct eth_hdr *) packet;
	ip_header = (const struct ip_hdr *) (packet + ETH_HDR_LEN);
	tcp_header = (const struct tcp_hdr *) (packet + ETH_HDR_LEN + IP_HDR_LEN);
	int tcp_header_length, total_header_size, pkt_data_len, i;
	int tcp_header_size = 4 * tcp_header->tcp_offset;

	total_header_size = ETH_HDR_LEN+IP_HDR_LEN+tcp_header_size;
	pkt_data_len = cap_header->len - total_header_size;

// if neither ip is a loopback addr, and the dest ip in the packet is the host ip

	if ( equals(inet_ntoa(ip_header->ip_dest_addr), host_ip)
	    && !(ip_header->ip_src_addr.s_addr == 0) && !(ip_header->ip_dest_addr.s_addr == 0)) {

		if (isSYNPkt(packet+ETH_HDR_LEN+sizeof(struct ip_hdr))) {

			alert_user(eth_header, tcp_header, ip_header, "TCP SYN SCAN", graphfd);
			timestamp(logfd);
			alert_user(eth_header, tcp_header, ip_header, "TCP SYN SCAN", logfd);

		} // SYN if
		else if (isFINPkt(packet+ETH_HDR_LEN+IP_HDR_LEN) && ((int) ip_header->ip_type == 6) && ((int) eth_header->ether_type == 8)) {

			alert_user(eth_header, tcp_header, ip_header, "FIN SCAN", graphfd);
			timestamp(logfd);
			alert_user(eth_header, tcp_header, ip_header, "FIN SCAN", logfd);

		} // FIN if
		else if (isXMASPkt(packet+ETH_HDR_LEN+IP_HDR_LEN)) {

			alert_user(eth_header, tcp_header, ip_header, "XMAS SCAN", graphfd);
			timestamp(logfd);
			alert_user(eth_header, tcp_header, ip_header, "XMAS SCAN", logfd);

		} // XMAS if
		else if (isNULLPkt(packet+ETH_HDR_LEN+IP_HDR_LEN) && (ip_header->ip_type == 6) && (eth_header->ether_type == 8)) {

			alert_user(eth_header, tcp_header, ip_header, "NULL SCAN", graphfd);
			timestamp(logfd);
			alert_user(eth_header, tcp_header, ip_header, "NULL SCAN", logfd);

		} // NULL if
		else if (isNULLPkt(packet+ETH_HDR_LEN+IP_HDR_LEN) && (ip_header->ip_type == 17) && (eth_header->ether_type == 8)) {

			alert_user(eth_header, tcp_header, ip_header, "UDP SCAN", graphfd);
			timestamp(logfd);
			alert_user(eth_header, tcp_header, ip_header, "UDP SCAN", logfd);

		} // UDP if

	}

} // caught_packet

// takes TCP header and checks for flags
int isNULLPkt(const u_char *header_start) {

	const struct tcp_hdr *tcp_header = (const struct tcp_hdr *)header_start;

	return !(tcp_header->tcp_flags & TCP_SYN) && !(tcp_header->tcp_flags & TCP_URG)
		&& !(tcp_header->tcp_flags & TCP_RST) && !(tcp_header->tcp_flags & TCP_PUSH)
		&& !(tcp_header->tcp_flags & TCP_ACK) && !(tcp_header->tcp_flags & TCP_FIN);

} // isNULLPkt

// takes TCP header and checks for FIN flags, returns 1 if true
int isFINPkt(const u_char *header_start) {

	const struct tcp_hdr *tcp_header = (const struct tcp_hdr *)header_start;

	if (tcp_header->tcp_flags & TCP_SYN) return 0;

	if (tcp_header->tcp_flags & TCP_URG) return 0; 
	
	if (tcp_header->tcp_flags & TCP_RST) return 0;

	if (tcp_header->tcp_flags & TCP_PUSH) return 0;

	if (tcp_header->tcp_flags & TCP_ACK) return 0;

	return tcp_header->tcp_flags & TCP_FIN;
	

} // isFINPkt

// takes TCP header and checks for FIN, PSH, and URG flags,  returns 1 if true
int isXMASPkt(const u_char *header_start) {

	const struct tcp_hdr *tcp_header = (const struct tcp_hdr *)header_start;

	if (tcp_header->tcp_flags & TCP_SYN) return 0;
	
	if (tcp_header->tcp_flags & TCP_RST) return 0;

	if (tcp_header->tcp_flags & TCP_ACK) return 0;

	return tcp_header->tcp_flags & TCP_FIN && tcp_header->tcp_flags & TCP_PUSH && tcp_header->tcp_flags & TCP_URG;

} // isXMASPkt

// takes TCP header and checks for SYN flags, returns 1 if true
int isSYNPkt(const u_char *header_start) {

	const struct tcp_hdr *tcp_header = (const struct tcp_hdr *)header_start;
	int header_size = 4 * tcp_header->tcp_offset;

	if (tcp_header->tcp_flags & TCP_FIN) return 0;

	if (tcp_header->tcp_flags & TCP_URG) return 0; 
	
	if (tcp_header->tcp_flags & TCP_RST) return 0;

	if (tcp_header->tcp_flags & TCP_PUSH) return 0;

	if (tcp_header->tcp_flags & TCP_ACK) return 0;

	return tcp_header->tcp_flags & TCP_SYN;

} // isSYNPkt

