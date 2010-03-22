#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#ifdef WINVER
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

typedef unsigned char u_char;
typedef unsigned char byte;
typedef unsigned int ip_t;
typedef unsigned short port_t;

typedef struct
{
	byte seg[6];
} mac_t;

typedef struct
{
	mac_t dstmac;
	mac_t srcmac;
	unsigned short type;
} etherheader;

typedef struct
{
	byte header_len;
	byte diff_serv_field;
	unsigned short len;
	unsigned short ident;
	byte flags;
	byte fragoffset;
	byte ttl;
	byte protocol;
	unsigned short checksum;
	unsigned int srcip;
	unsigned int dstip;
} ipheader;

typedef struct
{
	port_t srcport;
	port_t dstport;
	unsigned int seqnum;
	unsigned int unused;
	byte header_len;
	byte flags;
	unsigned short window_size;
	unsigned short checksum;
	byte options[8];
} tcpheader;

typedef struct
{
	port_t srcport;
	port_t dstport;
	unsigned short len;
	unsigned short checksum;
} udpheader;


typedef struct
{
	ip_t srcip;
	ip_t dstip;
	byte reserved;
	byte ptcl;
	unsigned short tcpl;
} psdipheader;


unsigned short checksum(unsigned short *buffer, int size)
{
	unsigned long cksum=0;
	while(size > 1)
	{
		cksum += *buffer++;
		size -=sizeof(unsigned short);
	}
	if (size)
		cksum += *(unsigned char *)buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);
	return (unsigned short)(~cksum);
}


int open_udp()
{
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		perror("socket");
		exit(1);
	}

	return s;
}


int main(int argc, char *argv[])
{
	if (argc != 5)
	{
		printf("Usage: %s INTERFACE CLIENT_IP SERVER_IP SERVER_PORT\n", argv[0]);
		printf("CLIENT_IP can be \"auto\" if you have a public IP address on the interface.\n");
		pcap_if_t *alldevs;
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_findalldevs(&alldevs, errbuf);
		pcap_if_t *d;
		if (!alldevs)
		{
			printf("Cannot find any interfaces; are you root?\n");
			exit(1);
		}
		for(d=alldevs; d; d=d->next)
		{
			printf("%s", d->name);
			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}
		exit(1);
	}
#ifdef WINVER
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2,0), &wsaData);
#endif

	int sr = open_udp();
	pcap_t *ph = pcap_open_live(argv[1], 8192, 0, 1, NULL);
	if (ph == NULL)
	{
		printf("pcap_open_live %s failed\n", argv[1]);
		exit(1);
	}

	struct pcap_pkthdr *header;
	u_char *pkt_data;

	for (;;)
	{

		int res = pcap_next_ex(ph, &header, (const u_char **) &pkt_data);


		if (res==1)
		{
			etherheader *ethh = (etherheader *) pkt_data;

			int p = 0;

			//			cout << "type: " << ethh->type << endl;
			if (ethh->type == 0x0008) // ip
			{

				p += sizeof(etherheader);
				ipheader *iph = (ipheader *) (pkt_data + p);


				if (iph->ttl <= 10)
				{
					printf("forward packet, size = %d\n", header->len - sizeof(etherheader));
					switch (iph->protocol)
					{
						case 0x06: // tcp
						case 0x11: // udp

							p += sizeof(ipheader);

							tcpheader *tcph;
							udpheader *udph;

							tcph = (tcpheader *) (pkt_data + p);
							udph = (udpheader *) (pkt_data + p);

							if (strcmp(argv[2], "auto") != 0)
								iph->srcip = inet_addr(argv[2]);

							iph->ttl = 64;
							psdipheader psdiph;
							psdiph.dstip = iph->dstip;
							psdiph.srcip = iph->srcip;
							psdiph.reserved = 0;
							psdiph.ptcl = iph->protocol;
							byte pseudoheader[8192];
							if (iph->protocol == 0x06) // tcp
							{
								tcph->checksum = 0;
								psdiph.tcpl = htons(htons(iph->len) - sizeof(ipheader));
								memcpy(pseudoheader, &psdiph, sizeof(psdiph));
								memcpy(pseudoheader+sizeof(psdiph), tcph, htons(iph->len)-sizeof(ipheader));
								/*
								   cout << "dumping pseudoheader:";
								   for (int i=0;i<header->len - p + sizeof(psdiph);i++)
								   cout << hex << setw(2) << setfill('0') << (int) pseudoheader[i] << ' ';
								   */
								tcph->checksum = checksum((unsigned short *) pseudoheader, sizeof(psdiph)+htons(iph->len)-sizeof(ipheader));
								//tcph->checksum -= htons(tcph->flags);
							}
							else
							{
								udph->checksum = 0;
								psdiph.tcpl = htons(htons(iph->len) - sizeof(ipheader));
								memcpy(pseudoheader, &psdiph, sizeof(psdiph));
								memcpy(pseudoheader+sizeof(psdiph), udph, htons(iph->len)-sizeof(ipheader));

								udph->checksum = checksum((unsigned short *) pseudoheader, sizeof(psdiph)+htons(iph->len)-sizeof(ipheader));
							}


							iph->checksum = 0;
							iph->checksum = checksum((unsigned short *) iph, sizeof(ipheader));

							//								pcap_sendpacket(ph, pkt_data, header->len);

							struct sockaddr_in sa = {0};
							sa.sin_family = AF_INET;
							sa.sin_addr.s_addr = inet_addr(argv[3]);
							sa.sin_port = htons(atoi(argv[4]));
							
							int i;
							for (i=0; i<header->len - sizeof(etherheader); i++)
								((char *)iph)[i] ^= 0x5a;
							sendto(sr, (const char*)iph, header->len - sizeof(etherheader), 0, (struct sockaddr*)&sa, sizeof(sa));



					}
				}
			}
		}
	}
	pcap_close(ph);
	return 0;
}
