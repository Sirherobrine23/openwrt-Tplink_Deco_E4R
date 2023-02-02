/*
 * Based on code found at https://dev.openwrt.org/ticket/4876 .
 * Extended by Jo-Philipp Wich <jow@openwrt.org> for use in OpenWrt.
 *
 * You may use this program under the terms of the GPLv2 license.
 */

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#define RESOLVEIP_ERROR_FILE 	"/tmp/resolveip_error"

enum RESOLVEIP_ERROR {
	RESOLVEIP_SUCCESS = 0,
	RESOLVEIP_ERR_TIMEOUT, 
	RESOLVEIP_ERR_HOSTNAME
};

static void print_result(int error)
{
	FILE *fd = NULL;
	unlink(RESOLVEIP_ERROR_FILE);

	fd = fopen(RESOLVEIP_ERROR_FILE, "w+");
	if (fd == NULL)
	{
		exit(-1);
	}
	fprintf(fd, "%d\n", error);
	fclose(fd);
}
static void abort_query(int sig)
{
	print_result(RESOLVEIP_ERR_TIMEOUT);
	exit(1);
}

static void show_usage(void)
{
	printf("Usage:\n");
	printf("	resolveip -h\n");
	printf("	resolveip [-t timeout] hostname\n");
	printf("	resolveip -4 [-t timeout] hostname\n");
	printf("	resolveip -6 [-t timeout] hostname\n");
	exit(255);
}

int main(int argc, char **argv)
{
	int timeout = 3;
	int opt;
	char ipaddr[INET6_ADDRSTRLEN];
	void *addr;
	struct addrinfo *res, *rp;
	struct sigaction sa = {	.sa_handler = &abort_query };
	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags    = 0
	};

	while ((opt = getopt(argc, argv, "46t:h")) > -1)
	{
		switch ((char)opt)
		{
			case '4':
				hints.ai_family = AF_INET;
				break;

			case '6':
				hints.ai_family = AF_INET6;
				break;

			case 't':
				timeout = atoi(optarg);
				if (timeout <= 0)
					show_usage();
				break;

			case 'h':
				show_usage();
				break;
		}
	}

	if (!argv[optind])
		show_usage();

	sigaction(SIGALRM, &sa, NULL);
	alarm(timeout);

	if (getaddrinfo(argv[optind], NULL, &hints, &res))
	{
		print_result(RESOLVEIP_ERR_HOSTNAME);
		exit(2);
	}

	for (rp = res; rp != NULL; rp = rp->ai_next)
	{
		addr = (rp->ai_family == AF_INET)
			? (void *)&((struct sockaddr_in *)rp->ai_addr)->sin_addr
			: (void *)&((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr
		;

		if (!inet_ntop(rp->ai_family, addr, ipaddr, INET6_ADDRSTRLEN - 1))
			exit(3);
		print_result(RESOLVEIP_SUCCESS);
		printf("%s\n", ipaddr);
	}

	freeaddrinfo(res);
	exit(0);
}
