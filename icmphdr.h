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

#define ICMP_ECHOREPLY           0        /* Echo Reply                        */
#define ICMP_DEST_UNREACH        3        /* Destination Unreachable        */
#define ICMP_SOURCE_QUENCH       4        /* Source Quench                */
#define ICMP_REDIRECT            5        /* Redirect (change route)        */
#define ICMP_ECHO                8        /* Echo Request                        */
#define ICMP_TIME_EXCEEDED       11        /* Time Exceeded                */
#define ICMP_PARAMETERPROB       12        /* Parameter Problem                */
#define ICMP_TIMESTAMP           13        /* Timestamp Request                */
#define ICMP_TIMESTAMPREPLY      14        /* Timestamp Reply                */
#define ICMP_INFO_REQUEST        15        /* Information Request                */
#define ICMP_INFO_REPLY          16        /* Information Reply                */
#define ICMP_ADDRESS             17        /* Address Mask Request                */
#define ICMP_ADDRESSREPLY        18        /* Address Mask Reply                */