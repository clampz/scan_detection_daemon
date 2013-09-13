/* net_structs.h
 * written by: David Weinman
 * last update: 08/21/13
 * */

/* note: this code was heavily influenced by Jon Erikson's
   'Hacking: The Art of Exploitation' */

#include <sys/types.h>
#include <netinet/in.h>

/* Ethernet Header */

// ------ constants

#define ETH_ADDR_LEN 6
#define ETH_HDR_LEN 14
#define IP_HDR_LEN 20

// ------ definitions

struct eth_hdr {

	unsigned char dest_eth_addr[ETH_ADDR_LEN]; // Destination MAC address
	unsigned char src_eth_addr[ETH_ADDR_LEN]; // Source MAC address

	unsigned short ether_type; // Type of Ethernet packet

};

/* Internet Protocol Header */
struct ip_hdr {

	unsigned char ip_version_and_header_length; // version and header length combined
	unsigned char ip_tos;          // type of service
	unsigned short ip_len;         // total length
	unsigned short ip_id;          // identification number
	unsigned short ip_frag_offset; // fragment offset and flags
#define IP_RF 0x8000                    // reserved fragment flag /
#define IP_DF 0x4000                    // dont fragment flag /
#define IP_MF 0x2000                    // more fragments flag /
#define IP_OFFMASK 0x1fff 
	unsigned char ip_ttl;          // time to live
	unsigned char ip_type;         // protocol type
	unsigned short ip_checksum;    // checksum
	//long unsigned int ip_src_addr;
	//long unsigned int ip_dest_addr;
	struct in_addr ip_src_addr;
	struct in_addr ip_dest_addr; // source & destination IP addresses

};

/* Transmission Control Protocol Header */

struct tcp_hdr {

	unsigned short tcp_src_port;
	unsigned short tcp_dest_port;
	unsigned int tcp_seq;
	unsigned int tcp_ack;
	unsigned char reserved:4; // 4 bits fom the 6 of reserved space
	unsigned char tcp_offset:4; // TCP data offset for little-endian host
	unsigned char tcp_flags; // TCP flags (and 2 bits from reserved space)

	#define TCP_FIN 0x01
	#define TCP_SYN 0x02
	#define TCP_RST 0x04
	#define TCP_PUSH 0x08
	#define TCP_ACK 0x10
	#define TCP_URG 0x20

	unsigned short tcp_window; // TCP window size
	unsigned short tcp_checksum;
	unsigned short tcp_urgent; // TCP urgent pointer

};




