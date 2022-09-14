#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/time.h>

#include "icmphdr.h"

#define BUF_SIZE 1024

// htons could be used too
#define SWAP_ENDIANESS_16(n) ((n & 0xff) << 8 | (n >> 8))

int				verbose = 0;
int				help = 0;
char			*host = NULL;
struct addrinfo	*addr;
char			ip[INET6_ADDRSTRLEN];

int				packets_count = 0;
int				packets_received = 0;
float			round_trip_min = 0;
float			round_trip_avg = 0;
float			round_trip_max = 0;
float			round_trip_stddev = 0;

int				ttl = 37;

// https://www.gnu.org/software/gnu-c-manual/gnu-c-manual.html#Initializing-Structure-Members

int		show_help(void)
{
	fprintf(stderr, "usage: ft_ping [-v]\n");
	return (64);
}

int		error_resolution(const char *host)
{
	fprintf(stderr, "ping: cannot resolve %s: Unknown host\n", host);
	return (68);
}

void	statistics(void)
{
	printf("\n");
	printf("--- %s ft_ping statistics ---\n", host);
	printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
		packets_count,
		packets_received,
		(1 - (float)packets_received / packets_count) * 100
	);
	exit(0);
}

int	sock;

// https://www.rfc-editor.org/rfc/rfc6450.html#section-3
// https://fr.wikipedia.org/wiki/Internet_Control_Message_Protocol
// https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
// Data is send in network byte order (big endian)

void	craft_ping_option(char **ptr, uint16_t type, uint16_t length, char *data)
{
	*(*ptr)++ = type >> 8;
	*(*ptr)++ = type % 0xFF;
	*(*ptr)++ = length >> 8;
	*(*ptr)++ = length % 0xFF;
	for (int i = 0; i < length; ++i)
		*(*ptr)++ = data[i];
}

char	*craft_u32(uint32_t n)
{
	static char	buf[4];
	int			i = 4;

	while (i)
	{
		buf[--i] = n & 0xFF;
		n >>= 8;
	}
	return (buf);
}

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

icmphdr_t	craft_ping_packet(uint16_t icmp_seq)
{
	icmphdr_t	icmphdr;
	memset(&icmphdr, 0, sizeof(icmphdr));
	icmphdr.type = ICMP_ECHO;
	icmphdr.code = 0;
	icmphdr.un.echo.id = SWAP_ENDIANESS_16(getpid());
	icmphdr.un.echo.sequence = SWAP_ENDIANESS_16(icmp_seq);

	return (icmphdr);
}

typedef struct {
	icmphdr_t	icmphdr;
	char		message[64 - sizeof(icmphdr_t)];
}	ping_packer_t;

void	ping(void)
{
	uint16_t	icmp_seq = packets_count;
	int			ttl = 0;
	float		time = 0;

	errno = 0;
	ping_packer_t	ping_packet = {
		craft_ping_packet(icmp_seq),
		"0123456789"
	};
	ping_packet.icmphdr.checksum = checksum(&ping_packet, sizeof(ping_packet));

	sendto(sock, &ping_packet, sizeof(ping_packet), 0, addr->ai_addr, addr->ai_addrlen);

	// https://stackoverflow.com/questions/51833241/recvmsg-returns-resource-temporarily-unavailable
	errno = 0;
	char			iovbuf[1024];
	struct iovec	iov = { iovbuf, BUF_SIZE };
	char			controlbuf[1024];
	struct msghdr	msg;
	memset(&msg, 0, sizeof(msg));
	// msg.msg_name = addr->ai_addr,
	// msg.msg_namelen = addr->ai_addrlen,
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = controlbuf;
	msg.msg_controllen = sizeof(controlbuf);

	++packets_count;
	ssize_t	len = recvmsg(sock, &msg, 0);

	if (len > 0) {
		printf("recved %ld\n", write(1, iovbuf, len));
		printf("recved %ld\n", write(1, controlbuf, len));
		++packets_received;
	}

	printf("%zd bytes from %s: icmp_seq=%d ttl=%d time=%.3f\n", len, ip, icmp_seq, ttl, time);

	alarm(1);
}

int		main(int ac, const char **av)
{
	while (--ac)
	{
		if (*av[ac] == '-')
		{
			if (av[ac][1] == 'v' && av[ac][2] == '\0')
				verbose = 1;
			else
				help = 1;
		}
		else if (host)
			help = 1;
		else
			host = (char *)av[ac];
	}

	if (!host || help)
		return (show_help());

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;

	if (getaddrinfo(host, NULL, &hints, &addr) < 0)
		return (error_resolution(host));

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0)
	{
		perror("ping: socket");
		exit(1);
	}

	// if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
	// 	perror("ping: setsockopt SO_RCVTIMEO");
	// 	exit(1);
	// }

	struct timeval timeout = {1, 0};
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		perror("ping: setsockopt SO_RCVTIMEO");
		exit(1);
	}

	// int	hincl = 1;
	// Inform the kernel do not fill up the headers' structure, we fabricated our own
	// https://stackoverflow.com/questions/48338190/sending-custom-tcp-packet-using-sendto-in-c
	// if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl)) < 0) {
	// 	perror("ping: setsockopt");
	// 	exit(1);
	// }

	inet_ntop(addr->ai_family, &((struct sockaddr_in *)addr->ai_addr)->sin_addr, ip, INET6_ADDRSTRLEN);
	printf("PING %s (%s): 64 data bytes\n", host, ip);

	signal(SIGALRM, (void (*)())ping);
	ping();

	signal(SIGINT, (void (*)())statistics);

	while (1);

	return (0);
}