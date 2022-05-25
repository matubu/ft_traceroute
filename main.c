#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#define BUF_SIZE 1024

int		verbose = 0;
int		help = 0;
char	*host = NULL;
struct addrinfo	*addr;
char	ip[INET6_ADDRSTRLEN];

int		packets_count = 0;
int		packets_received = 0;
float	round_trip_min = 0;
float	round_trip_avg = 0;
float	round_trip_max = 0;
float	round_trip_stddev = 0;

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

void	ping(void)
{
	int		icmp_seq = packets_count;
	int		ttl = 0;
	float	time = 0;

	errno = 0;
	ssize_t	sent = sendto(sock, "Hello world", 11, 0, addr->ai_addr, addr->ai_addrlen);
	printf("sent %ld\n", sent);
	
	perror("sendto");

	char			buf[BUF_SIZE];
	struct iovec	iov = {buf, BUF_SIZE};
	struct msghdr	msg = {
		.msg_name = addr->ai_addr,
		.msg_namelen = addr->ai_addrlen,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0
	};
	errno = 0;
	ssize_t	len = recvmsg(sock, &msg, 0);
	// ssize_t	len = 0;

	perror("recvmsg");
	printf("msg received\n");
	if (len > 0)
		printf("write %ld\n", write(1, buf, len));

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

	if (getaddrinfo(host, "0", 0, &addr) < 0)
		return (error_resolution(host));

	sock = socket(addr->ai_family, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0)
	{
		printf("ping: socket: Operation not permitted\n");
		exit(1);
	}

	inet_ntop(addr->ai_family, &((struct sockaddr_in *)addr->ai_addr)->sin_addr, ip, INET6_ADDRSTRLEN);
	printf("PING %s (%s): 56 data bytes\n", host, ip);

	signal(SIGALRM, (void (*)())ping);
	ping();

	signal(SIGINT, (void (*)())statistics);

	while (1);

	return (0);
}