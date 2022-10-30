#pragma once

#include <sys/time.h>
#include <string.h>

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

#define iss(s, const_s) !memdiff(const_s, s, sizeof(const_s))

void	die(char *s) {
	fprintf(stderr, "traceroute: %s\n", s);
	exit(1);
}

int	is_digit(int c) {
	return (c >= '0' && c <= '9');
}

uint64_t	parse_u64(const char *s) {
	if (!s || !is_digit(*s)) {
		die("expected a unsigned number");
	}
	uint64_t	n = 0;
	while (is_digit(*s)) {
		n = n * 10 + *s - '0';
		++s;
	}
	return (n);
}