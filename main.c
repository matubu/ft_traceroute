#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <float.h>
#include <math.h>

#include "malloc.h"
#include "icmphdr.h"
#include "utils.h"

// https://hpd.gasmi.net/

#define PCK_SIZE 40
#define PCK_DATA_SIZE (PCK_SIZE - sizeof(icmphdr_t))

#define RECV_BUFSIZE 1024

#define SWAP_ENDIANESS_16(n) ((n & 0xff) << 8 | (n >> 8))

uint16_t	checksum(void *data_ptr, size_t data_size) {
	uint16_t	*data = data_ptr;
	uint64_t	sum = 0;

	while (data_size >= sizeof(*data)) {
		sum += *data++;
		data_size -= sizeof(*data);
	}
	if (data_size) {
		sum += *(uint8_t *)data;
	}

	while (sum & ~0xffff) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return (~sum);
}

void	craft_traceroute_packet(icmphdr_t *buf)
{
	buf->type = ICMP_ECHO;
	buf->code = 0;
	buf->checksum = 0;
	buf->un.echo.id = SWAP_ENDIANESS_16(getpid());
	buf->un.echo.sequence = SWAP_ENDIANESS_16(1);

	for (uint64_t i = 0; i < PCK_DATA_SIZE; ++i) {
		((char *)buf)[sizeof(icmphdr_t) + i] = i % 3 + 1;
	}

	buf->checksum = checksum(buf, PCK_SIZE);
}

void	help() {
	puts("Usage:");
	puts("  ./traceroute host");
	puts("Options:");
	puts("  --help      Read this help and exit");
	puts("  -4          Use IPv4");
	puts("  -I          Use ICMP ECHO for tracerouting");
	puts("  -d          Enable socket level debugging");
	puts("  -f first_ttl");
	puts("      Start from the first_ttl hop (instead from 1)");
	puts("  -m max_ttl");
	puts("      Set the max number of hops (max TTL to be reached). Default is 30");
	puts("  -q nqueries");
	puts("      Set the number of probes per each hop. Default is 3");
	puts("");
	puts("Arguments:");
	puts("  host        The host to traceroute to");
	exit(1);
}

int		main(int ac, char **av)
{
	/** Parse */

	if (ac < 2) {
		help();
	}

	char		*host = NULL;
	int			debug = 0;
	uint64_t	first_hop = 1;
	uint64_t	max_hops = 30;
	uint64_t	probes_per_hop = 3;

	for (int i = 1; i < ac; ++i) {
		if (av[i][0] == '-') {
			if (iss(av[i], "-4") || iss(av[i], "-I")) {
			}
			else if (iss(av[i], "-d")) {
				debug = 1;
			}
			else if (iss(av[i], "-f")) {
				first_hop = parse_u64(av[++i]);
				if (first_hop == 0) {
					die("first hop out of range");
				}
			}
			else if (iss(av[i], "-q")) {
				probes_per_hop = parse_u64(av[++i]);
				if (probes_per_hop <= 0 || probes_per_hop > 10) {
					die("no more than 10 probes per hop");
				}
			}
			else if (iss(av[i], "-m")) {
				max_hops = parse_u64(av[++i]);
				if (max_hops <= 0) {
					die("first hop out of range");
				}
				if (max_hops > 255) {
					die("max hops cannot be more than 255");
				}
			}
			else if (iss(av[i], "--help")) {
				help();
			}
			else {
				die("unknown flag");
			}
		} else {
			if (host) {
				die("host already defined");
			}
			host = av[i];
		}
	}

	if (host == NULL) {
		help();
	}
	if (first_hop > max_hops) {
		die("first hop out of range");
	}

	/** Setup */

	struct addrinfo	*addr;

	struct addrinfo hints = {0};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;

	if (getaddrinfo(host, NULL, &hints, &addr) < 0) {
		fprintf(stderr, "traceroute: cannot resolve %s: Unknown host\n", host);
		exit(1);
	}

	int	sock = socket(addr->ai_family, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0) {
		perror("traceroute: could not create socket");
		exit(1);
	}

	struct timeval timeout = {1, 0};
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		perror("traceroute: setsockopt SO_RCVTIMEO");
		exit(1);
	}

	if (debug) {
		if (setsockopt(sock, SOL_SOCKET, SO_DEBUG, &debug, sizeof(debug)) < 0) {
			perror("traceroute: setsockopt SO_DEBUG");
			exit(1);
		}
	}

	uint64_t	hops = first_hop;

	char	hostip_s[INET6_ADDRSTRLEN];
	inet_ntop(addr->ai_family, &((struct sockaddr_in *)addr->ai_addr)->sin_addr, hostip_s, INET6_ADDRSTRLEN);

	printf("traceroute to %s (%s), %ld hops max, %ld byte packets\n",
		host, hostip_s,
		max_hops, PCK_SIZE + sizeof(struct ip)
	);

	/** Exec */

	while (hops <= max_hops) {
		if (setsockopt(sock, IPPROTO_IP, IP_TTL, &hops, sizeof(hops)) < 0) {
			perror("traceroute: setsockopt IP_TTL");
			exit(1);
		}

		printf("%2ld", hops);
		int	reached = 1;
		struct sockaddr_in	prev_addr = {};

		for (uint64_t i = 0; i < probes_per_hop; ++i) {
			char	buf[PCK_SIZE];
			craft_traceroute_packet((icmphdr_t *)buf);

			struct timeval	start = gettime();

			if (sendto(sock, buf, PCK_SIZE, 0, addr->ai_addr, addr->ai_addrlen) < 0) {
				perror("traceroute: sendto");
				exit(1);
			}

			char				recvbuf[RECV_BUFSIZE];
			struct sockaddr_in	r_addr;
			uint				addr_len = sizeof(r_addr);

			if (recvfrom(sock, &recvbuf, RECV_BUFSIZE, 0,
				(struct sockaddr*)&r_addr, &addr_len) < 0) {
				printf("  *");
				reached = 0;
				continue ;
			}

			struct timeval end = gettime();
			double	time = (double)(end.tv_sec - start.tv_sec) * 1000 + (double)(end.tv_usec - start.tv_usec) / 1000;

			char	ipbuf[INET6_ADDRSTRLEN];
			inet_ntop(r_addr.sin_family, &r_addr.sin_addr, ipbuf, sizeof(ipbuf));

			if (i == 0 || memdiff(&prev_addr, &r_addr, sizeof(r_addr))) {
				printf("  %s", ipbuf);
			}
			printf("  %.3f ms", time);

			prev_addr = r_addr;

			icmphdr_t	*icmp_res = (void *)recvbuf + sizeof(struct ip);

			if (icmp_res->type == 11) {
				reached = 0;
			}
		}

		printf("\n");

		if (reached) {
			break ;
		}

		++hops;
	}
}
