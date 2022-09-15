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
#include <netinet/ip.h>
#include <float.h>
#include <math.h>

#include "icmphdr.h"

#define BUF_SIZE 1024

// htons could be used too
#define SWAP_ENDIANESS_16(n) ((n & 0xff) << 8 | (n >> 8))

// TODO only one global variable
int				verbose = 0;
int				help = 0;
uint8_t			ttl = 37;
uint64_t		packet_size = 56;
uint64_t		data_size = 0;
int				count = -1;
int				quiet = 0;
uint64_t		interval = 1;

char			*host = NULL;
struct addrinfo	*addr;
char			ip[INET6_ADDRSTRLEN];

int				packets_count = 0;
int				packets_received = 0;
int				packets_error = 0;

typedef struct times_s {
	double				ms;
	struct times_s	*next;
}	times_t;
double			round_trip_min = DBL_MAX;
double			round_trip_avg = 0;
double			round_trip_max = 0;
times_t			*times = NULL;

int				sock;

#define malloc(n) ({ \
	void	*ptr = malloc(n); \
	if (ptr == NULL) { \
		fprintf(stderr, "ping: allocation failed\n"); \
		exit(1); \
	} \
	ptr; \
})

#define Error(fmt, ...) { \
	if (!quiet) \
		printf("From %s: icmp_seq=%d " fmt "\n", ip, icmp_seq, ##__VA_ARGS__); \
	++packets_error; \
	alarm(interval); \
	return ; \
}

// https://www.gnu.org/software/gnu-c-manual/gnu-c-manual.html#Initializing-Structure-Members

int		show_help(void)
{
	fprintf(stderr, "Usage: ft_ping [OPTIONS] HOST\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    -c CNT         Send only CNT pings\n");
	fprintf(stderr, "    -s SIZE        Send SIZE data bytes in packets (default 56)\n");
	fprintf(stderr, "    -i SECS        Interval\n");
	fprintf(stderr, "    -t TTL         Set TTL\n");
	fprintf(stderr, "    -q             Quiet, only display output at start/finish\n");
	fprintf(stderr, "    -v             Verbose output\n");

			// t =y
			// s =y
			// c =y
			// q =y
			// i =y
	return (64);
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

	if (packets_received == 0) {
		exit(1);
	}

	round_trip_avg /= packets_received;

	double			round_trip_stddev = 0;
	for (times_t *it = times; it != NULL; it = it->next) {
		double	deviation = it->ms - round_trip_avg;
		round_trip_stddev += deviation * deviation;
	}
	round_trip_stddev = sqrt(round_trip_stddev / packets_received);

	printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n", round_trip_min, round_trip_avg, round_trip_max, round_trip_stddev);
	exit(0);
}

// https://www.rfc-editor.org/rfc/rfc6450.html#section-3
// https://fr.wikipedia.org/wiki/Internet_Control_Message_Protocol
// https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
// Data is send in network byte order (big endian)

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

void	craft_ping_packet(icmphdr_t *buf, uint16_t icmp_seq)
{
	buf->type = ICMP_ECHO;
	buf->code = 0;
	buf->checksum = 0;
	buf->un.echo.id = SWAP_ENDIANESS_16(getpid());
	buf->un.echo.sequence = SWAP_ENDIANESS_16(icmp_seq);

	for (uint64_t i = 0; i < packet_size; ++i) {
		((char *)buf)[sizeof(icmphdr_t) + i] = i % 3 + 1;
	}

	buf->checksum = checksum(buf, data_size);
}

void	ErrorIcmpType(icmphdr_t	*received_packet, uint16_t icmp_seq) {
	switch (received_packet->type)
	{
		case ICMP_DEST_UNREACH:
			switch (received_packet->code) {
				case ICMP_NET_UNREACH: Error("Net Unreachable"); break ;
				case ICMP_HOST_UNREACH: Error("Host Unreachable"); break ;
				case ICMP_PROT_UNREACH: Error("Protocol Unreachable"); break ;
				case ICMP_PORT_UNREACH: Error("Port Unreachable"); break ;
				case ICMP_FRAG_NEEDED: Error("Fragmentation Needed and Don't Fragment was Set"); break ;
				case ICMP_SR_FAILED: Error("Source Route Failed"); break ;
				case ICMP_NET_UNKNOWN: Error("Destination Network Unknown"); break ;
				case ICMP_HOST_UNKNOWN: Error("Destination Host Unknown"); break ;
				case ICMP_HOST_ISOLATED: Error("Source Host Isolated"); break ;
				case ICMP_NET_ANO: Error("Communication with Destination Network is Administratively Prohibited"); break ;
				case ICMP_HOST_ANO: Error("Communication with Destination Host is Administratively Prohibited"); break ;
				case ICMP_NET_UNR_TOS: Error("Destination Network Unreachable for Type of Service"); break ;
				case ICMP_HOST_UNR_TOS: Error("Destination Host Unreachable for Type of Service"); break ;
				case ICMP_PKT_FILTERED: Error("Communication Administratively Prohibited"); break ;
				case ICMP_PREC_VIOLATION: Error("Host Precedence Violation"); break ;
				case ICMP_PREC_CUTOFF: Error("Precedence cutoff in effect"); break ;
				default: Error("Destination unreachable"); break ;
			}
		break ;

		case ICMP_SOURCE_QUENCH:
			Error("Source Quench");
		break ;

		case ICMP_REDIRECT:
			switch (received_packet->code) {
				case ICMP_REDIR_NET: Error("Redirect for Destination Network"); break ;
				case ICMP_REDIR_HOST: Error("Redirect for Destination Host"); break ;
				case ICMP_REDIR_NETTOS: Error("Redirect for Destination Network Based on Type-of-Service"); break ;
				case ICMP_REDIR_HOSTTOS: Error("Redirect for Destination Host Based on Type-of-Service"); break ;
				default: Error("Redirect"); break ;
			}
		break ;

		case ICMP_TIME_EXCEEDED:
			switch (received_packet->code) {
				case ICMP_EXC_TTL: Error("Time-to-Live Exceeded in Transit"); break ;
				case ICMP_EXC_FRAGTIME: Error("Fragment Reassembly Time Exceeded"); break ;
				default: Error("Time Exceeded"); break ;
			}
		break ;

		case ICMP_PARAMETERPROB:
			switch (received_packet->code) {
				case ICMP_ERRATPTR: Error("Pointer indicates the error"); break ;
				case ICMP_OPTABSENT: Error("Missing a Required Option"); break ;
				case ICMP_BAD_LENGTH: Error("Bad Length"); break ;
				default: Error("Parameter Problem"); break ;
			}
		break ;

		default:
			Error("Unknown (type=%d)", received_packet->type);
		break ;
	}
}

void	ping(void)
{
	uint16_t	icmp_seq = packets_count;

	char			buf[data_size];
	craft_ping_packet((icmphdr_t *)buf, icmp_seq);

	char			iovbuf[BUF_SIZE];
	struct iovec	iov = { iovbuf, sizeof(iovbuf) };
	struct msghdr	msg = {0};
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	struct timeval	start, end;
	if (gettimeofday(&start, NULL) < 0) {
		perror("ping: gettimeofday");
		exit(1);
	}

	sendto(sock, buf, data_size, 0, addr->ai_addr, addr->ai_addrlen);
	++packets_count;
	ssize_t	len = recvmsg(sock, &msg, 0);
	if (gettimeofday(&end, NULL) < 0) {
		perror("ping: gettimeofday");
		exit(1);
	}

	if (len == -1) {
		Error("%s", strerror(errno));
	}

	if (len < (ssize_t)(sizeof(struct ip) + sizeof(icmphdr_t))) {
		Error("Missing header");
	}

	icmphdr_t	*received_packet = (icmphdr_t *)(iovbuf + sizeof(struct ip));

	uint16_t	received_checksum = received_packet->checksum;
	received_packet->checksum = 0;

	if (received_checksum != checksum(received_packet, len - sizeof(struct ip))) {
		Error("Invalid checksum");
	}

	if (received_packet->type != ICMP_ECHOREPLY) {
		ErrorIcmpType(received_packet, icmp_seq);
		return ;
	}

	if (received_packet->code != 0) {
		Error("Invalid code (code=%d)", received_packet->code);
	}

	if (received_packet->un.echo.sequence != ((icmphdr_t *)buf)->un.echo.sequence) {
		Error("Wrong sequence id");
	}

	if (received_packet->un.echo.id != ((icmphdr_t *)buf)->un.echo.id) {
		Error("Wrong id");
	}

	if (len < (ssize_t)(sizeof(struct ip) + data_size)) {
		Error("Missing content");
	}

	for (size_t i = 0; i < packet_size; ++i) {
		if (((char *)received_packet + sizeof(icmphdr_t))[i] != i[buf + sizeof(icmphdr_t)]) {
			Error("Not same content");
		}
	}

	double		time = (double)(end.tv_sec - start.tv_sec) * 1000 + (double)(end.tv_usec - start.tv_usec) / 1000;

	round_trip_min = round_trip_min < time ? round_trip_min : time;
	round_trip_avg += time;
	round_trip_max = round_trip_max > time ? round_trip_max : time;

	times_t	*node = malloc(sizeof(times_t));
	node->ms = time;
	node->next = times;
	times = node;

	++packets_received;

	if (!quiet)
		printf("%zd bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n", len, ip, icmp_seq, ttl, time);

	if (count == packets_received) {
		statistics();
		exit(1);
	}
	alarm(interval);
}

int	is_digit(int c) {
	return (c >= '0' && c <= '9');
}

uint64_t	parse_u64(const char *s) {
	if (!is_digit(*s)) {
		fprintf(stderr, "ping: expected u8\n");
		exit(1);
	}
	uint64_t	n = 0;
	while (is_digit(*s)) {
		n = n * 10 + *s - '0';
		++s;
	}
	return (n);
}

int		main(int ac, const char **av)
{
	for (int i = 1; i < ac; ++i) {
		if (*av[i] == '-') {
			if (av[i][1] == '\0' || av[i][2] != '\0') {
				help = 1;
				break ;
			}
			switch (av[i][1]) {
				case 'v': verbose = 1; break ;
				case 'q': quiet = 1; break ;
				case 't':
					if (++i < ac) {
						ttl = parse_u64(av[i]);
					} else {
						help = 1;
					}
				break ;
				case 's':
					if (++i < ac) {
						packet_size = parse_u64(av[i]);
					} else {
						help = 1;
					}
				break ;
				case 'c':
					if (++i < ac) {
						count = parse_u64(av[i]);
					} else {
						help = 1;
					}
				break ;
				case 'i':
					if (++i < ac) {
						interval = parse_u64(av[i]);
					} else {
						help = 1;
					}
				break ;
				default:
					help = 1;
				break ;
			}
		}
		else if (host)
			help = 1;
		else
			host = (char *)av[i];
	}

	if (!host || help)
		return (show_help());

	struct addrinfo hints = {0};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;

	if (getaddrinfo(host, NULL, &hints, &addr) < 0) {
		fprintf(stderr, "ping: cannot resolve %s: Unknown host\n", host);
		exit(1);
	}

	sock = socket(addr->ai_family, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0) {
		perror("ping: socket");
		exit(1);
	}

	if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
		perror("ping: setsockopt IP_TTL");
		exit(1);
	}

	struct timeval timeout = {1, 0};
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		perror("ping: setsockopt SO_RCVTIMEO");
		exit(1);
	}

	inet_ntop(addr->ai_family, &((struct sockaddr_in *)addr->ai_addr)->sin_addr, ip, INET6_ADDRSTRLEN);

	data_size = packet_size + sizeof(icmphdr_t);
	printf("PING %s (%s): %ld data bytes\n", host, ip, data_size);

	signal(SIGALRM, (void (*)())ping);
	ping();

	signal(SIGINT, (void (*)())statistics);

	while (1);
}