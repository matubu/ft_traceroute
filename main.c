#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <float.h>
#include <math.h>

#include "malloc.h"
#include "icmphdr.h"

// https://hpd.gasmi.net/

#define PCK_SIZE 64
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

struct timeval	gettime() {
	struct timeval	time;
	if (gettimeofday(&time, NULL) < 0) {
		perror("ping: gettimeofday");
		exit(1);
	}
	return (time);
}

int	memdiff(void *a, void *b, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		if (((uint8_t *)a)[i] != ((uint8_t *)b)[i]) {
			return (1);
		}
	}
	return (0);
}

int		main(int ac, const char **av)
{
	if (ac != 2) {
		exit(1);
	}

	const char		*host = av[1];
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

	uint64_t	hops = 0;
	uint64_t	max_hops = 30;

	while (++hops < max_hops) {
		if (setsockopt(sock, IPPROTO_IP, IP_TTL, &hops, sizeof(hops)) < 0) {
			perror("traceroute: setsockopt IP_TTL");
			exit(1);
		}

		printf("%2ld", hops);
		int	reached = 1;
		struct sockaddr_in	prev_addr = {};

		for (int i = 0; i < 3; ++i) {
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
	}
}
