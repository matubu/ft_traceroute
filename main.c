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
		fprintf(stderr, "ping: cannot resolve %s: Unknown host\n", host);
		exit(1);
	}

	int	sock = socket(addr->ai_family, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0) {
		perror("ping: could not create socket");
		exit(1);
	}

	struct timeval timeout = {1, 0};
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		perror("ping: setsockopt SO_RCVTIMEO");
		exit(1);
	}

	uint64_t	i = 1;
	while (1) {
		if (setsockopt(sock, IPPROTO_IP, IP_TTL, &i, sizeof(i)) < 0) {
			perror("ping: setsockopt IP_TTL");
			exit(1);
		}

		char	buf[PCK_SIZE];
		craft_traceroute_packet((icmphdr_t *)buf);

		sendto(sock, buf, PCK_SIZE, 0, addr->ai_addr, addr->ai_addrlen);

		char				recvbuf[RECV_BUFSIZE];
		struct sockaddr_in	r_addr;
		uint				addr_len = sizeof(r_addr);

		recvfrom(sock, &recvbuf, RECV_BUFSIZE, 0,
			(struct sockaddr*)&r_addr, &addr_len);

		char	ipbuf[INET6_ADDRSTRLEN];
		inet_ntop(r_addr.sin_family, &r_addr.sin_addr, ipbuf, sizeof(ipbuf));

		printf("%ld: %s\n", i, ipbuf);

		icmphdr_t	*icmp_res = (void *)recvbuf + sizeof(struct ip);

		// for (int i = 0; i < 40; ++i) {
		// 	printf("%02x ", ((uint8_t *)recvbuf)[i]);
		// }

		printf("type=%d code=%d\n", icmp_res->type, icmp_res->code);

		if (icmp_res->type != 11) {
			break ;
		}

		++i;
	}
}
