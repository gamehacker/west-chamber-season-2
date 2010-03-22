#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


void socket_iphdrincl(int sd)
{
	const int one = 1;

	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL,
				(char *)&one, sizeof(one)) == -1)
	{
		perror("setsockopt");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("Usage: %s PORT\n", argv[0]);
		exit(1);
	}
	int sock_udp = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_udp == -1) {
		perror("socket");
		exit(1);
	}
	int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock_raw == -1) {
		perror("socket");
		exit(1);
	}
	socket_iphdrincl(sock_raw);

	struct sockaddr_in local = {0};
	local.sin_family=AF_INET;
	local.sin_port=htons(atoi(argv[1])); 
	local.sin_addr.s_addr=INADDR_ANY;

	bind(sock_udp,(struct sockaddr*)&local,sizeof(local));

	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;

	int total = 0;
	while (1) {
		unsigned char buf[2048];
		int len = recv(sock_udp, buf, sizeof(buf), 0);
		printf("forward packet, size = %d, total = %d KB\n", len, (total += len) / 1024);
		int i;
		for (i=0; i<len; i++)
			buf[i] ^= 0x5a;
		sa.sin_addr.s_addr = *(unsigned int *)&buf[16];
		sendto(sock_raw, buf, len, 0, (struct sockaddr*)&sa, sizeof(sa));
	}
	return 0;
}
