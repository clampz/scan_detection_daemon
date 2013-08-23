/* scan_detector.c
 * written by: David Weinman
 * last update: 08/16/13
 * */

#include <stdio.h>
#include <pcap/pcap.h>

#include "malloc_dump.h"
#include "net_structs.h"


void scan_fatal(const char *, const char *);
void main(int, char **);
void caught_packet(u_char*, const struct pcap_pkthdr*, const u_char*);
int isSYNPkt(const u_char*);

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

	device = pcap_lookupdev(errbuf);

	if (device == NULL) {
		scan_fatal("pcap_lookupdev", errbuf);
	}

	pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);

// just testing with diff while loop condition
	while (i++ < atoi(argv[1])) {

		if (i > 1) pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
		printf("pkt # %d. ", i);
		pcap_loop(pcap_handle, 1, caught_packet, NULL);
		pcap_close(pcap_handle);
	
	}

	return;

}

// checks for SYN flag and writes info if it finds one
void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {

	const struct eth_hdr *eth_header = (const struct eth_hdr *) packet;
	const struct ip_hdr *ip_header = (const struct ip_hdr *) packet + ETH_HDR_LEN;
	const struct tcp_hdr *tcp_header = (const struct tcp_hdr *) packet + ETH_HDR_LEN + sizeof(struct ip_hdr);
	int tcp_header_length, total_header_size, pkt_data_len, i;
	int header_size = 4 * tcp_header->tcp_offset;
	u_char *pkt_data;

	if (isSYNPkt(packet+ETH_HDR_LEN+sizeof(struct ip_hdr))) {

		
        	tcp_header_length = 4 * tcp_header->tcp_offset;
	        total_header_size = ETH_HDR_LEN+sizeof(struct ip_hdr)+tcp_header_length;

		pkt_data = (u_char *)packet + total_header_size;
		pkt_data_len = cap_header->len - total_header_size;

		printf("\nsrc mac addr: %02x", eth_header->src_eth_addr[0]);
		for (i = 1; i < ETH_ADDR_LEN; i++) printf(":%02x", eth_header->src_eth_addr[i]);

		printf(" | dst mac addr: %02x", eth_header->dest_eth_addr[0]);
		for (i = 1; i < ETH_ADDR_LEN; i++) printf(":%02x", eth_header->dest_eth_addr[i]);

		puts("\n");

		printf("\nsrc ip addr: %d  |  dst ip addr: %d\n", inet_ntoa(ip_header->ip_src_addr), inet_ntoa(ip_header->ip_dest_addr));
		printf("\ntype: %u\n", (u_int) ip_header->ip_type);
		printf("\nID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));

		dump(pkt_data, pkt_data_len);

	}

}

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

}

/*
void decode_eth(char *printString, const u_char *packet) {

	int i;
	const struct eth_hdr *ethernet_header;

	ethernet_header = (const struct eth_hdr *) header_start;
	snprintf(printString, MAX_PRINT_LEN, "[[  Layer 2 :: Ethernet Header  ]]\n[ Source: %02x", ethernet_header->ether_src_addr[0]);

}*/

/* PSEUDO CODE

pkArr = define const size array for packets

while true {

	for (i = 0; i < 10; i++) {

		recieve a tcp packet
		append it to pkArr
		if packet has only SYN up {
			recieve a packet
			if packet has SYN and RST up {
				print detection and dump packets
			}
		}

	}

}

*/


