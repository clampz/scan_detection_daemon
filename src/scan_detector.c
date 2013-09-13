/* scan_detector.c
 * written by: David Weinman
 * last update: 08/16/13
 * */

/*

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int open(const char *pathname, int flags, mode_t mode);
int open(const char *pathname, int flags);
ssize_t write(int fd, const void *buf, size_t count);

#include <pcap/pcap.h>

char *pcap_lookupdev(char *errbuf);
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
void pcap_close(pcap_t *p);

#include <arpa/inet.h>

char *inet_ntoa(struct in_addr in);

#include <stdio.h>

int printf(const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);
int fprintf(FILE * restrict stream, const char * restrict format, ...);

#include <time.h>

struct tm *localtime(const time_t *timep);
size_t strftime(char *s, size_t max, const char *format, const struct tm *tm);

*/


#include <sys/types.h>
#include <sys/stat.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "malloc_dump.h"
#include "net_structs.h"
//#include "hash_t.h"

// constants for (printout??) purposes
//#define SCAN_ALERT_PRINT_1 "\n-------------------\n\n       NETWORK SCAN ALERT (TYPE: "
//#define SCAN_ALERT_PRINT_2 ")\n\n-------------------\n"

#define LOGFILE "/var/logs/scandetectd.log" // log filename
#define GRAPHFILE "/var/logs/scandetectd_graph.log" // graph log filename

void handle_shutdown(int);
void scan_fatal(const char *, const char *);
void caught_packet(u_char*, const struct pcap_pkthdr*, const u_char*);
void alert_user(const struct eth_hdr*, const struct tcp_hdr*, const struct ip_hdr*, const char*, int);
void timestamp(int); // writes a timestamp to the open file descriptor 
int main(int, char **);
int isSYNPkt(const u_char*);
int isFINPkt(const u_char*);
int isXMASPkt(const u_char*);
int isNULLPkt(const u_char*);
int isUDPkt(const u_char*);
int get_file_size(int); // returns the filesize of open file descriptor 

// host ip string pointer
char *host_ip;

// global packet capture loop counter, log and graph file descriptors
int pcap_loop_cnt, logfd, graphfd;

// This function is called when the process is killed 
void handle_shutdown(int signal) {
   timestamp(logfd);
   write(logfd, "Shutting down..\n", 16);
   close(logfd);
   close (graphfd);
   exit(0);
}

// an error function
void scan_fatal(const char *failed_in, const char *errbuf) {

        printf("Fatal Error in %s:", failed_in);
	fatal((char *) errbuf);
        exit(1);

}

/*

string pointers for captures of scans
size of incoming ips
size of various strings
profits????!!!

*/

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

	//printf("Sniffing on device %s\n", device);

	pcap_loop_cnt = 0;

	while (1) {
//		fdprintf(logfd, 30, "\n154:for loop main: %d\n ", i++);
		if (i > 1) pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
		pcap_loop(pcap_handle, atoi(argv[2]), caught_packet, NULL);
		pcap_close(pcap_handle);
	}

	return 0;

}

void alert_user( const struct eth_hdr *eth_header, const struct tcp_hdr *tcp_header, 
		const struct ip_hdr *ip_header, const char *type, int fd) {

	char *src_addr, *dest_addr; // filebuf; ??
	int i;


//puts("\n2\n");
//	printf("%s%s%s", SCAN_ALERT_PRINT_1, type, SCAN_ALERT_PRINT_2);

//	printf("\nsrc mac addr: %02x", eth_header->src_eth_addr[0]);
//	for (i = 1; i < ETH_ADDR_LEN; i++) printf(":%02x", eth_header->src_eth_addr[i]);

//	puts("\n");

	fdprintf(fd, 46, "\n\"[%s] src ip: %s\" ", type, inet_ntoa(ip_header->ip_src_addr));
	//fprintf(logfd, "\n\"[%s] src ip: %s\" ", type, src_addr);
//	snprintf(filebuf, (size_t) 45, "\n\"[%s] src ip: %s\" ", type, src_addr");

//	printf("\n\"[%s] src ip: %s\" ", type, src_addr); 3 + 12 + 10 + 17 + 2 

	fdprintf(fd, 34, "-- \"dst ip: %s\";\n", inet_ntoa(ip_header->ip_dest_addr));
	//fprintf(logfd, "-- \"dst ip: %s\";\n", dest_addr);
//	snprintf(filebuf, (size_t) 33, "-- \"dst ip: %s\";\n", dest_addr);

  //      printf("-- \"dst ip: %s\";\n", dest_addr); 12 + 17 + 3

}

// --VERBOSE ONE
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

//	fdprintf(logfd, 23, "\ncaught packet #%d\n", ++pcap_loop_cnt);

//	fdprintf(logfd, 63, "\npkt # %d, src_ip: %s, len: %d. ", pcap_loop_cnt, inet_ntoa(ip_header->ip_src_addr), pkt_data_len);

	
//	fdprintf(logfd, 25, "220:condition in cp = %d", ( equals(inet_ntoa(ip_header->ip_dest_addr), host_ip)
  //          && !(ip_header->ip_src_addr.s_addr == 0) && !(ip_header->ip_dest_addr.s_addr == 0)));

// if neither ip is a loopback addr, and the dest ip in the packet is the host ip
	if ( equals(inet_ntoa(ip_header->ip_dest_addr), host_ip)
	    && !(ip_header->ip_src_addr.s_addr == 0) && !(ip_header->ip_dest_addr.s_addr == 0)) {

		//printf(" -- targeted!! -- ip_type == %d, ether_type == %d\n", (ip_header->ip_type), (eth_header->ether_type));

//puts("\n1\n");

// if the packet has only a SYN flag up
		if (isSYNPkt(packet+ETH_HDR_LEN+sizeof(struct ip_hdr))) {

			alert_user(eth_header, tcp_header, ip_header, "TCP SYN SCAN", graphfd);
			alert_user(eth_header, tcp_header, ip_header, "TCP SYN SCAN", logfd);

		} // SYN if
		else if (isFINPkt(packet+ETH_HDR_LEN+IP_HDR_LEN) && ((int) ip_header->ip_type == 6) && ((int) eth_header->ether_type == 8)) {

			alert_user(eth_header, tcp_header, ip_header, "FIN SCAN", graphfd);
			alert_user(eth_header, tcp_header, ip_header, "FIN SCAN", logfd);

		} // FIN if
		else if (isXMASPkt(packet+ETH_HDR_LEN+IP_HDR_LEN)) {

			alert_user(eth_header, tcp_header, ip_header, "XMAS SCAN", graphfd);
			alert_user(eth_header, tcp_header, ip_header, "XMAS SCAN", logfd);

		} // XMAS if
		else if (isNULLPkt(packet+ETH_HDR_LEN+IP_HDR_LEN) && (ip_header->ip_type == 6) && (eth_header->ether_type == 8)) {

			alert_user(eth_header, tcp_header, ip_header, "NULL SCAN", graphfd);
			alert_user(eth_header, tcp_header, ip_header, "NULL SCAN", logfd);

		} // NULL if
		else if (isNULLPkt(packet+ETH_HDR_LEN+IP_HDR_LEN) && (ip_header->ip_type == 17) && (eth_header->ether_type == 8)) {

			alert_user(eth_header, tcp_header, ip_header, "UDP SCAN", graphfd);
			alert_user(eth_header, tcp_header, ip_header, "UDP SCAN", logfd);

		} // UDP if

	} //else { // ip loopback if
	
	 //} // else if not loopback

} // caught_packet

// takes TCP header and checks for flags
int isNULLPkt(const u_char *header_start) {

	const struct tcp_hdr *tcp_header = (const struct tcp_hdr *)header_start;
	//fdprintf(logfd, 23, "\ncaught packet #%d\n", ++pcap_loop_cnt);

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

/* This function writes a timestamp string to the open file descriptor 
 * passed to it. 
 */
void timestamp(int fd) {
   time_t now;
   struct tm *time_struct;
   int length;
   char time_buffer[40];

   time(&now);  // get number of seconds since epoch 
   time_struct = localtime((const time_t *)&now); // convert to tm struct 
   length = strftime(time_buffer, 40, "%m/%d/%Y %H:%M:%S> ", time_struct);
   write(fd, time_buffer, length); // write timestamp string to log 
}


/* This function accepts an open file descriptor and returns     
 * the size of the associated file. Returns -1 on failure. 
 */
int get_file_size(int fd) {
   struct stat stat_struct;

   if(fstat(fd, &stat_struct) == -1)
      return -1;
   return (int) stat_struct.st_size;
}



