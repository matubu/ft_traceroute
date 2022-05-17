#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>

int show_help()
{
	fprintf(stderr, "usage: ft_ping [-v]\n");
	return (64);
}

int	error_resolution(const char *host)
{
	fprintf(stderr, "ping: cannot resolve %s: Unknown host\n", host);
	return (68);
}

int	main(int ac, const char **av)
{
	int		verbose = 0;
	int		help = 0;
	char	*host = NULL;

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

	printf("%d %s\n", verbose, host);

	struct addrinfo *addr;

	if (getaddrinfo(host, "80", 0, &addr) != 0)
		return (error_resolution(host));

	char	buf[INET6_ADDRSTRLEN];
	inet_ntop(addr->ai_family, &((struct sockaddr_in *)addr->ai_addr)->sin_addr, buf, INET6_ADDRSTRLEN);

	printf("PING %s (%s): 56 data bytes\n", host, buf);

	freeaddrinfo(addr);

	return (0);
}