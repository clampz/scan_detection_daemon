/* scan_detector.c
 * written by: David Weinman
 * last update: 08/16/13
 * */

#include <stdio.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

#include "malloc_dump.h"
#include "net_structs.h"

#define SCAN_ALERT_PRINT_1 "\n-------------------\n\n       NETWORK SCAN ALERT (TYPE: "
#define SCAN_ALERT_PRINT_2 ")\n\n-------------------\n"

void scan_fatal(const char *, const char *);
void main(int, char **);
void caught_packet(u_char*, const struct pcap_pkthdr*, const u_char*);
int isSYNPkt(const u_char*);
int isFINPkt(const u_char*);
int isXMASPkt(const u_char*);
void alert_user(const struct eth_hdr*, const struct tcp_hdr*, const struct ip_hdr*, const char*);

char *host_ip;

// an error function
void scan_fatal(const char *failed_in, const char *errbuf) {

        printf("Fatal Error in %s:", failed_in);
	fatal((char *) errbuf);
        exit(1);

}

// main creates a listener and captures packets while looking 
// for SYN flags in the TCP header
void main(int argc, char ** argv) {

	int i = 0;
        struct pcap_pkthdr cap_header;
        const u_char *packet, *pkt_data;
        char errbuf[PCAP_ERRBUF_SIZE];
        char *device;
	pcap_t *pcap_handle;
	host_ip = argv[1];

	if (argc != 3) {printf("\nwrong # of args.\n\n"); exit(1);} 

	device = pcap_lookupdev(errbuf);

	if (device == NULL) {
		scan_fatal("pcap_lookupdev", errbuf);
	}

	pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);

// just testing with diff while loop condition
	while (i++ < atoi(argv[2])) {

		if (i > 1) pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
		printf("pkt # %d. ", i);
		pcap_loop(pcap_handle, 1, caught_packet, NULL);
		pcap_close(pcap_handle);

	}

	return;

}

void alert_user( const struct eth_hdr *eth_header, const struct tcp_hdr *tcp_header, 
		const struct ip_hdr *ip_header, const char *type) {

	char *src_addr, *dest_addr;
	int i;

//puts("\n2\n");
	printf("%s%s%s", SCAN_ALERT_PRINT_1, type, SCAN_ALERT_PRINT_2);

	printf("\nsrc mac addr: %02x", eth_header->src_eth_addr[0]);
	for (i = 1; i < ETH_ADDR_LEN; i++) printf(":%02x", eth_header->src_eth_addr[i]);

	puts("\n");

	src_addr = inet_ntoa(ip_header->ip_src_addr);
	printf("src ip addr: %s \n\n", src_addr);

        dest_addr = inet_ntoa(ip_header->ip_dest_addr);
        printf("| dst ip addr: %s\n", dest_addr);

}

// checks for SYN flag and writes info if it finds one
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

//puts("\n1\n");

// if the packet has only a SYN flag up
		if (isSYNPkt(packet+ETH_HDR_LEN+sizeof(struct ip_hdr))) {

	//		alert_user((const struct eth_hdr *) packet, (const struct tcp_hdr *)\
	//			    packet + ETH_HDR_LEN, (const struct ip_hdr *) \
	//			    packet + ETH_HDR_LEN + IP_HDR_LEN, "STEALTH SYN SCAN");

			alert_user(eth_header, tcp_header, ip_header, "TCP SYN SCAN");

		} // SYN if
		else if (isFINPkt(packet+ETH_HDR_LEN+IP_HDR_LEN)) {

			alert_user(eth_header, tcp_header, ip_header, "FIN SCAN");

		} // FIN if
		else if (isXMASPkt(packet+ETH_HDR_LEN+IP_HDR_LEN)) {

			alert_user(eth_header, tcp_header, ip_header, "XMAS SCAN");

		} // XMAS if
		else if (((int) ip_header->ip_type) == 6 && ((int) eth_header->ether_type) == 8) {

			alert_user(eth_header, tcp_header, ip_header, "NULL SCAN");

		} // NULL if
		else if (((int) ip_header->ip_type) == 17 && ((int) eth_header->ether_type) == 8) {

			alert_user(eth_header, tcp_header, ip_header, "UDP SCAN");

		} // UDP if

	} else { // ip loopback if
	
	} // else if not loopback

} // caught_packet

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

