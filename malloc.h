#pragma once

#include <stdlib.h>

#define malloc(n) ({ \
	void	*ptr = malloc(n); \
	if (ptr == NULL) { \
		fprintf(stderr, "ping: allocation failed\n"); \
		exit(1); \
	} \
	ptr; \
})
