#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

int main() {
	printf("%d\n", socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
}