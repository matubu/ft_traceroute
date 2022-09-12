#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include "icmphdr.h"

#define BUF_SIZE 1024

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
	return (sum);
}

icmphdr_t	craft_ping_packet(uint16_t icmp_seq)
{
	return ((icmphdr_t){
		.type = ICMP_ECHO,
		.code = 0,
		.un.echo.id = SWAP_ENDIANESS_16(getpid()),
		.un.echo.sequence = SWAP_ENDIANESS_16(icmp_seq)
	});
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
		"bonjour google"
	};
	ping_packet.icmphdr.checksum = checksum(&ping_packet, sizeof(ping_packet));

	ssize_t	sent = sendto(sock, &ping_packet, sizeof(ping_packet), 0, addr->ai_addr, addr->ai_addrlen);
	printf("sent %ld/%ld\n", sent, sizeof(ping_packet));

	printf("%d\n", errno);
	perror("sendto");

	errno = 0;
	char			recvbuf[BUF_SIZE];
	struct iovec	iov = { recvbuf, BUF_SIZE };
	char			controlbuf[BUF_SIZE];
	struct msghdr	msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = &controlbuf,
		.msg_controllen = sizeof(controlbuf)
	};
	printf("recvmsg...\n");
	ssize_t	len = recvmsg(sock, &msg, 0);
	// ssize_t	len = 0;

	perror("recvmsg");
	printf("msg received\n");
	if (len > 0) {
		printf("recved %ld\n", write(1, recvbuf, len));
		printf("recved %ld\n", write(1, controlbuf, len));
	}

	++packets_count;
	//++packets_received;
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

	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_RAW,
		.ai_protocol = IPPROTO_ICMP
	};
	if (getaddrinfo(host, NULL, &hints, &addr) < 0)
		return (error_resolution(host));

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0)
	{
		perror("ping: socket");
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