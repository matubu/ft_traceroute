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

#define RECV_BUFSIZE 1024

#define SWAP_ENDIANESS_16(n) ((n & 0xff) << 8 | (n >> 8))

typedef struct trips_s {
	double				ms;
	struct trips_s	*next;
}	trips_t;

typedef struct {
	int				verbose;
	uint64_t		ttl;
	uint64_t		packet_size;
	int				count;
	int				quiet;
	uint64_t		interval;

	char			*host;

	int				packets_count;
	int				packets_received;
	double			round_trip_min;
	double			round_trip_max;
	double			round_trip_total;
	trips_t			*trips;

	int				sock;
	struct addrinfo	*addr;
	char			ip[INET6_ADDRSTRLEN];
	uint64_t		data_size;
}	t_state;

t_state	g = {
	.verbose = 0,
	.ttl = 37,
	.packet_size = 56,
	.count = -1,
	.quiet = 0,
	.interval = 1,

	.host = NULL,

	.packets_count = 0,
	.packets_received = 0,
	.round_trip_min = DBL_MAX,
	.round_trip_max = 0,
	.round_trip_total = 0,
	.trips = NULL,
};

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
	return (64);
}

void	statistics(void)
{
	printf("\n");
	printf("--- %s ft_ping statistics ---\n", g.host);
	printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
		g.packets_count,
		g.packets_received,
		(1 - (float)g.packets_received / g.packets_count) * 100
	);

	if (g.packets_received == 0) {
		exit(1);
	}

	double	round_trip_avg = g.round_trip_total / g.packets_received;

	double	round_trip_stddev = 0;
	for (trips_t *it = g.trips; it != NULL; it = it->next) {
		double	deviation = it->ms - round_trip_avg;
		round_trip_stddev += deviation * deviation;
	}
	round_trip_stddev = sqrt(round_trip_stddev / g.packets_received);

	printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n", g.round_trip_min, round_trip_avg, g.round_trip_max, round_trip_stddev);
	exit(0);
}

void	next() {
	if (g.count == g.packets_count) {
		statistics();
		exit(1);
	}
	alarm(g.interval);
}

#define Error(fmt, ...) { \
	if (!g.quiet && g.verbose) \
		printf("From %s: icmp_seq=%d " fmt "\n", g.ip, icmp_seq, ##__VA_ARGS__); \
	next(); \
	return ; \
}

// https://www.rfc-editor.org/rfc/rfc6450.html#section-3
// https://fr.wikipedia.org/wiki/Internet_Control_Message_Protocol
// https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
// note: Data is send in network byte order (big endian)

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

	for (uint64_t i = 0; i < g.packet_size; ++i) {
		((char *)buf)[sizeof(icmphdr_t) + i] = i % 3 + 1;
	}

	buf->checksum = checksum(buf, g.data_size);
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
	uint16_t	icmp_seq = g.packets_count;

	char			buf[g.data_size];
	craft_ping_packet((icmphdr_t *)buf, icmp_seq);

	char			iovbuf[RECV_BUFSIZE];
	struct iovec	iov = { iovbuf, sizeof(iovbuf) };
	struct msghdr	msg = {0};
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	struct timeval	start, end;
	if (gettimeofday(&start, NULL) < 0) {
		perror("ping: gettimeofday");
		exit(1);
	}

	sendto(g.sock, buf, g.data_size, 0, g.addr->ai_addr, g.addr->ai_addrlen);
	++g.packets_count;
	ssize_t	len = recvmsg(g.sock, &msg, 0);
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

	if (len < (ssize_t)(sizeof(struct ip) + g.data_size)) {
		Error("Missing content");
	}

	for (size_t i = 0; i < g.packet_size; ++i) {
		if (((char *)received_packet + sizeof(icmphdr_t))[i] != i[buf + sizeof(icmphdr_t)]) {
			Error("Not same content");
		}
	}

	double		time = (double)(end.tv_sec - start.tv_sec) * 1000 + (double)(end.tv_usec - start.tv_usec) / 1000;

	g.round_trip_min = g.round_trip_min < time ? g.round_trip_min : time;
	g.round_trip_max = g.round_trip_max > time ? g.round_trip_max : time;
	g.round_trip_total += time;

	trips_t	*node = malloc(sizeof(trips_t));
	node->ms = time;
	node->next = g.trips;
	g.trips = node;

	++g.packets_received;

	if (!g.quiet)
		printf("%zd bytes from %s: icmp_seq=%d ttl=%ld time=%.3f ms\n", len, g.ip, icmp_seq, g.ttl, time);

	next();
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

void	parse_arguments(int ac, const char **av) {
	for (int i = 1; i < ac; ++i) {
		if (*av[i] == '-') {
			if (av[i][1] == '\0' || av[i][2] != '\0')
				exit(show_help());
			switch (av[i][1]) {
				case 'v': g.verbose = 1; break ;
				case 'q': g.quiet = 1; break ;
				case 't':
					if (++i >= ac)
						exit(show_help());
					g.ttl = parse_u64(av[i]);
				break ;
				case 's':
					if (++i >= ac)
						exit(show_help());
					g.packet_size = parse_u64(av[i]);
				break ;
				case 'c':
					if (++i >= ac)
						exit(show_help());
					g.count = parse_u64(av[i]);
				break ;
				case 'i':
					if (++i >= ac)
						exit(show_help());
					g.interval = parse_u64(av[i]);
				break ;
				default:
					exit(show_help());
				break ;
			}
		}
		else if (g.host)
			exit(show_help());
		else
			g.host = (char *)av[i];
	}

	if (!g.host)
		exit(show_help());
}

int		main(int ac, const char **av)
{
	parse_arguments(ac, av);

	struct addrinfo hints = {0};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;

	if (getaddrinfo(g.host, NULL, &hints, &g.addr) < 0) {
		fprintf(stderr, "ping: cannot resolve %s: Unknown host\n", g.host);
		exit(1);
	}

	g.sock = socket(g.addr->ai_family, SOCK_RAW, IPPROTO_ICMP);
	if (g.sock < 0) {
		perror("ping: socket");
		exit(1);
	}

	if (setsockopt(g.sock, IPPROTO_IP, IP_TTL, &g.ttl, sizeof(g.ttl)) < 0) {
		perror("ping: setsockopt IP_TTL");
		exit(1);
	}

	struct timeval timeout = {1, 0};
	if (setsockopt(g.sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		perror("ping: setsockopt SO_RCVTIMEO");
		exit(1);
	}

	inet_ntop(g.addr->ai_family, &((struct sockaddr_in *)g.addr->ai_addr)->sin_addr, g.ip, INET6_ADDRSTRLEN);

	g.data_size = g.packet_size + sizeof(icmphdr_t);
	printf("PING %s (%s): %ld data bytes\n", g.host, g.ip, g.data_size);

	signal(SIGALRM, (void (*)())ping);
	signal(SIGINT, (void (*)())statistics);

	ping();

	while (1);
}