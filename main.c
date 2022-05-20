#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

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
	puts("");
	printf("--- %s ft_ping statistics ---\n", host);
	printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
		packets_count,
		packets_received,
		(1 - (float)packets_received / packets_count) * 100
	);
	exit(0);
}

void	ping(void)
{
	int		icmp_seq = packets_count;
	int		ttl = 0;
	float	time = 0;
	++packets_count;
	alarm(5);

	int	sock = socket(addr->ai_family, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0)
	{
		printf("%d\n", AF_INET == addr->ai_family);
		puts("ping: socket: Operation not permitted");
		return ;
	}
	else
		printf("yes");
	// if (bind(sock, addr->ai_addr, sizeof(*addr->ai_addr)) < 0)
	// {
	// 	printf("bind failed\n");
	// 	return ;
	// }
	// printf("test\n");
	// sendto(sock, "Hello world", 11, 0, addr->ai_addr, sizeof(*addr->ai_addr));

	// struct msghdr	msg;
	// ssize_t	len = recvmsg(sock, &msg, 0);
	ssize_t	len = 0;

	//++packets_received;
	printf("%zd bytes from %s: icmp_seq=%d ttl=%d time=%.3f\n", len, ip, icmp_seq, ttl, time);
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

	if (getaddrinfo(host, "0", 0, &addr) != 0)
		return (error_resolution(host));

	inet_ntop(addr->ai_family, &((struct sockaddr_in *)addr->ai_addr)->sin_addr, ip, INET6_ADDRSTRLEN);

	printf("PING %s (%s): 56 data bytes\n", host, ip);
	
	signal(SIGALRM, (void (*)())ping);
	ping();

	signal(SIGINT, (void (*)())statistics);

	while (1);

	return (0);
}