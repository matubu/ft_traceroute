#pragma once

#include <stdint.h>

// http://www.rajivchakravorty.com/source-code/.tmp/snort-html/structicmphdr.html
// http://www.rajivchakravorty.com/source-code/.tmp/snort-html/struct__ICMPHdr.html
// https://pcapplusplus.github.io/api-docs/v22.05/structpcpp_1_1icmphdr.html
// https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip_icmp.h.html
typedef struct
{ 
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	union 
	{ 
		struct
		{ 
			uint16_t id; 
			uint16_t sequence; 
		} echo;
		uint32_t   gateway;
		struct
		{ 
			uint16_t __unused; 
			uint16_t mtu; 
		} frag;
	} un; 
}	icmphdr_t;

// Types
#define ICMP_ECHOREPLY           0         /* Echo Reply                        */
#define ICMP_DEST_UNREACH        3         /* Destination Unreachable        */
#define ICMP_SOURCE_QUENCH       4         /* Source Quench                */
#define ICMP_REDIRECT            5         /* Redirect (change route)        */
#define ICMP_ECHO                8         /* Echo Request                        */
#define ICMP_TIME_EXCEEDED       11        /* Time Exceeded                */
#define ICMP_PARAMETERPROB       12        /* Parameter Problem                */
#define ICMP_TIMESTAMP           13        /* Timestamp Request                */
#define ICMP_TIMESTAMPREPLY      14        /* Timestamp Reply                */
#define ICMP_INFO_REQUEST        15        /* Information Request                */
#define ICMP_INFO_REPLY          16        /* Information Reply                */
#define ICMP_ADDRESS             17        /* Address Mask Request                */
#define ICMP_ADDRESSREPLY        18        /* Address Mask Reply                */

/* Codes for UNREACH. */
#define ICMP_NET_UNREACH         0         /* Network Unreachable                */
#define ICMP_HOST_UNREACH        1         /* Host Unreachable                */
#define ICMP_PROT_UNREACH        2         /* Protocol Unreachable                */
#define ICMP_PORT_UNREACH        3         /* Port Unreachable                */
#define ICMP_FRAG_NEEDED         4         /* Fragmentation Needed/DF set        */
#define ICMP_SR_FAILED           5         /* Source Route failed                */
#define ICMP_NET_UNKNOWN         6
#define ICMP_HOST_UNKNOWN        7
#define ICMP_HOST_ISOLATED       8
#define ICMP_NET_ANO             9
#define ICMP_HOST_ANO            10
#define ICMP_NET_UNR_TOS         11
#define ICMP_HOST_UNR_TOS        12
#define ICMP_PKT_FILTERED        13        /* Packet filtered */
#define ICMP_PREC_VIOLATION      14        /* Precedence violation */
#define ICMP_PREC_CUTOFF         15        /* Precedence cut off */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET           0        /* Redirect Net                        */
#define ICMP_REDIR_HOST          1        /* Redirect Host                */
#define ICMP_REDIR_NETTOS        2        /* Redirect Net for TOS                */
#define ICMP_REDIR_HOSTTOS       3        /* Redirect Host for TOS        */

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL             0        /* TTL count exceeded                */
#define ICMP_EXC_FRAGTIME        1        /* Fragment Reass time exceeded        */