#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <pcap/pcap.h>

#define MODE_UDP_UDP 0
#define MODE_UDP_TCP 1
#define MODE_TCP_UDP 2
#define MODE_UDP_ICMP 3
#define MODE_ICMP_UDP 4
#define MTU_SIZE 1500

#define IP_SIZE sizeof(struct sockaddr_in6)
#define ETHHDR_LEN 14
#define ETHHDR_TYPE_OFFSET 12
#define IPHDR_LEN 20
#define IPHDR_SRC_OFFSET 12
#define IP6HDR_LEN 40
#define IP6HDR_SRC_OFFSET 9
#define ICMP_LEN 8
#define ICMP_SEQ_OFFSET 6
#define ICMP_SKIP (IPHDR_LEN + ICMP_LEN)
#define ICMP6_SKIP (ICMP_LEN)
#define PCAP_ICMP_SKIP (ETHHDR_LEN + IPHDR_LEN + ICMP_LEN)
#define PCAP_ICMP6_SKIP (ETHHDR_LEN + IP6HDR_LEN + ICMP_LEN)

#define min(X, Y) (((X) < (Y)) ? (X) : (Y))

static volatile sig_atomic_t run = 1;
static int sockets[10];

struct session
{
    // boolean flags
    int mode;
    int verbose;
    int obfuscate;
    int pcap;
    int prefer_v4;

    // local server configured with -l
    struct sockaddr_in6 local_addr;
    int local_port;
    int server_fd;

    // remote gateway or end server configured with -r
    struct sockaddr_in6 remote_addr;
    int remote_port;
    int remote_fd;

    // address of the connecting client to local server
    struct sockaddr_in6 client_addr;
    int client_fd;

    // protocol-dependent stateful variables
    int connected;
    unsigned short sequence;
    pcap_t *cap_ptr;
};

static void sig_handler(int _)
{
    (void)_;

    if (run == 0)
    {
        kill(getpid(), SIGKILL);
        return;
    }

    run = 0;
    printf("Exiting...\n");

    for (int i = 0; i < sizeof(sockets) / sizeof(int); i++)
    {
        if (sockets[i] != 0)
        {
            close(sockets[i]);
            shutdown(sockets[i], SHUT_RDWR);
        }
    }
}

static inline void obfuscate_message(char* message, int length)
{
    int process = min(16, length);

    if (length > 32)
    {
        for (int i = 0; i < process; i++)
        {
            message[i] ^= 'a' ^ message[i + 16];
        }
    }
    else
    {
        for (int i = 0; i < process; i++)
        {
            message[i] ^= 'a';
        }
    }
}

static inline unsigned short read_14bit(int fd)
{
    int shift = 0;
    unsigned short value = 0;
    unsigned char current = 0;
    
    do
    {
        if (shift == 2 * 7) // cap at 16383
        {
            printf("Size header seems to be corrupted, abandoning read.\n");
            break;
        }

        socklen_t msglen = read(fd, &current, sizeof(unsigned char));

        if (msglen == 0)
        {
            // propagate TCP closed event
            return 0;
        }

        value |= (current & 0x7f) << shift;
        shift += 7;
    }
    while ((current & 0x80) != 0);

    return value;
}

static inline void write_14bit(unsigned short size, char* buffer, int* length)
{
    *length = 0;
    unsigned short value = size;

    while (value >= 0x80)
    {
        buffer[(*length)++] = value | 0x80;
        value >>= 7;
    }

    buffer[(*length)++] = value;
}

static inline unsigned short ip_checksum(char* data, unsigned int length)
{
    unsigned long long acc = 0xffff;

    unsigned int offset = ((unsigned long)data)&3;
    if (offset)
    {
        unsigned int count = 4-offset;
        if (count > length)
        {
            count = length;
        }

        unsigned int word = 0;
        memcpy(offset + (char*)&word, data, count);
        acc += ntohl(word);
        data += count;
        length -= count;
    }

    char* data_end = data+(length&~3);
    while (data != data_end)
    {
        unsigned int word;
        memcpy(&word, data, 4);
        acc += ntohl(word);
        data += 4;
    }
    length &= 3;

    if (length)
    {
        unsigned int word = 0;
        memcpy(&word, data, length);
        acc += ntohl(word);
    }

    acc = (acc&0xffffffff)+(acc>>32);
    while (acc >> 16)
    {
        acc = (acc&0xffff)+(acc>>16);
    }

    if (offset & 1)
    {
        acc = ((acc&0xff00)>>8)|((acc&0x00ff)<<8);
    }

    return htons(~acc);
}

void hexdump(const void* data, size_t size)
{
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';

	for (i = 0; i < size; ++i)
    {
		printf("%02X ", ((unsigned char*)data)[i]);

		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~')
        {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
        else
        {
			ascii[i % 16] = '.';
		}

		if ((i+1) % 8 == 0 || i+1 == size)
        {
			printf(" ");

			if ((i+1) % 16 == 0)
            {
				printf("|  %s \n", ascii);
			}
            else if (i+1 == size)
            {
				ascii[(i+1) % 16] = '\0';

				if ((i+1) % 16 <= 8)
                {
					printf(" ");
				}

				for (j = (i+1) % 16; j < 16; ++j)
                {
					printf("   ");
				}

				printf("|  %s \n", ascii);
			}
		}
	}
}

void print_ip(struct sockaddr_in6 *sockaddr)
{
    int offset = 0;
    char addrstr[INET6_ADDRSTRLEN];
    
    if (sockaddr->sin6_family == AF_INET)
    {
        if (inet_ntop(sockaddr->sin6_family, &((struct sockaddr_in*)sockaddr)->sin_addr, (char*)&addrstr, sizeof(*sockaddr)) == NULL)
        {
            return;
        }

        printf("native");
    }
    else if (sockaddr->sin6_family == AF_INET6)
    {
        if (inet_ntop(sockaddr->sin6_family, &sockaddr->sin6_addr, (char*)&addrstr, sizeof(*sockaddr)) == NULL)
        {
            return;
        }

        if (IN6_IS_ADDR_V4MAPPED(&sockaddr->sin6_addr))
        {
            offset = strlen("::ffff:");
            printf("mapped");
        }
    }

    printf("%s", addrstr + offset);
}

static inline void downgrade_v4mapped(struct sockaddr_in6 *sockaddr)
{
    // downgrade v4-mapped IPv6 in sockaddr_in6 addresses to IPv4 sockaddr_in
    // this is required for raw sockets, as they do not work with v4-mapped addresses

    if (sockaddr->sin6_family == AF_INET || !IN6_IS_ADDR_V4MAPPED(&sockaddr->sin6_addr))
    {
        return;
    }

    ((uint8_t*)&((struct sockaddr_in*)sockaddr)->sin_addr)[0] = ((uint8_t*)&sockaddr->sin6_addr)[12];
    ((uint8_t*)&((struct sockaddr_in*)sockaddr)->sin_addr)[1] = ((uint8_t*)&sockaddr->sin6_addr)[13];
    ((uint8_t*)&((struct sockaddr_in*)sockaddr)->sin_addr)[2] = ((uint8_t*)&sockaddr->sin6_addr)[14];
    ((uint8_t*)&((struct sockaddr_in*)sockaddr)->sin_addr)[3] = ((uint8_t*)&sockaddr->sin6_addr)[15];

#ifdef BSD
    sockaddr->sin6_len = sizeof(struct sockaddr_in);
#endif
    sockaddr->sin6_family = AF_INET;
}

static inline void upgrade_v4mapped(struct sockaddr_in6 *sockaddr)
{
    // upgrade IPv4 sockaddr_in addresses to v4-mapped IPv6 in sockaddr_in6
    // otherwise, address set from recvfrom() will not be usable for sendto() on AF_INET6

    if (sockaddr->sin6_family == AF_INET6)
    {
        return;
    }

    ((uint8_t*)&sockaddr->sin6_addr)[12] = ((uint8_t*)&((struct sockaddr_in*)sockaddr)->sin_addr)[0];
    ((uint8_t*)&sockaddr->sin6_addr)[13] = ((uint8_t*)&((struct sockaddr_in*)sockaddr)->sin_addr)[1];
    ((uint8_t*)&sockaddr->sin6_addr)[14] = ((uint8_t*)&((struct sockaddr_in*)sockaddr)->sin_addr)[2];
    ((uint8_t*)&sockaddr->sin6_addr)[15] = ((uint8_t*)&((struct sockaddr_in*)sockaddr)->sin_addr)[3];
    ((uint32_t*)&sockaddr->sin6_addr)[0] = 0;
    ((uint32_t*)&sockaddr->sin6_addr)[1] = 0;
    ((uint32_t*)&sockaddr->sin6_addr)[2] = 0;
    ((uint16_t*)&sockaddr->sin6_addr)[5] = 0xffff;

#ifdef BSD
    sockaddr->sin6_len = sizeof(struct sockaddr_in6);
#endif
    sockaddr->sin6_family = AF_INET6;
    sockaddr->sin6_flowinfo = 0;
}

static inline void pcap_extract_source(const unsigned char* packet, const size_t len, struct sockaddr_in6 *sockaddr)
{
    if (len < ETHHDR_LEN + IPHDR_LEN)
    {
        return;
    }

    switch (packet[ETHHDR_TYPE_OFFSET])
    {
        case 0x86:
                sockaddr->sin6_family = AF_INET6;
                sockaddr->sin6_flowinfo = 0;
                *((struct in6_addr*)&sockaddr->sin6_addr) = *((struct in6_addr*)(packet + ETHHDR_LEN + IP6HDR_SRC_OFFSET - 1));
#ifdef BSD
                sockaddr->sin6_len = sizeof(struct sockaddr_in6);
#endif
            break;

        case 0x08:
                sockaddr->sin6_family = AF_INET;
                ((struct sockaddr_in*)sockaddr)->sin_addr = *((struct in_addr*)(packet + ETHHDR_LEN + IPHDR_SRC_OFFSET));
#ifdef BSD
                sockaddr->sin6_len = sizeof(struct sockaddr_in);
#endif
            break;
    }
    print_ip(sockaddr);
    // if eth ETHHDR_TYPE_OFFSET 12 byte == 0x86 -> ipv6
    // if ipv4 addr = ETHHDR_LEN + IPHDR_SRC_OFFSET -> 4 bytes
    // if ipv6 addr = ETHHDR_LEN + IP6HDR_SRC_OFFSET 10 -> 16 bytes
}

int resolve_host(const char *addr, struct sockaddr_in6 *sockaddr, int prefer_v4)
{
    int res;
    struct addrinfo hints, *addrs;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_V4MAPPED | AI_ALL | AI_ADDRCONFIG;

    if ((res = getaddrinfo(addr, NULL, &hints, &addrs)) != 0)
    {
        fprintf(stderr, "Failed to resolve host %s: %s\n", addr, gai_strerror(res));
        return res;
    }

    memset(sockaddr, 0, sizeof(*sockaddr));

    int found = 0;
    
    if (prefer_v4)
    {

        for (struct addrinfo *addr = addrs; addr != NULL; addr = addr->ai_next)
        {
            if (!IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)addr->ai_addr)->sin6_addr))
            {
                continue;
            }

            memcpy(sockaddr, addr->ai_addr, sizeof(*sockaddr));
            found = 1;
            break;
        }
    }

    if (!found)
    {
        memcpy(sockaddr, addrs->ai_addr, sizeof(*sockaddr));
    }

    freeaddrinfo(addrs);

    return res;
}

void print_help(char* argv[])
{
    printf("usage: %s -r addr:port [args]\narguments:\n\n", argv[0]);
    printf("   -r addr:port\tRemote host to tunnel packets to.\n");
    printf("   -l addr:port\tLocal listening address and port.\n   \t\t  Optional, defaults to 127.0.0.1:8080\n");
    printf("   -m mode\tOperation mode. Possible values:\n   \t\t  uu - UDP-to-UDP (Default)\n   \t\t  ut - UDP-to-TCP\n   \t\t  tu - TCP-to-UDP\n   \t\t  ui - UDP-to-ICMP (Requires root)\n   \t\t  tu - ICMP-to-UDP (Requires root)\n\n");
    printf("   -p\t\tUse PCAP, only applicable to ICMP tunnels, highly recommended.\n");
    printf("   -4\t\tPrefer IPv4 and only listen on IPv4 locally.\n");
    printf("   -o\t\tEnable generic header obfuscation.\n");
    printf("   -v\t\tDetailed logging at the expense of decreased throughput.\n");
    printf("   -h\t\tDisplays this message.\n");
}

int parse_arguments(int argc, char* argv[], struct session *s)
{
    char *token, *localhost = NULL, *remotehost = NULL;

    if (argc == 1)
    {
        print_help(argv);
        return EXIT_SUCCESS;
    }

    memset(s, 0, sizeof(*s));
    s->local_port = 8080;

    int opt;
    while((opt = getopt(argc, argv, "hm:l:r:4opv")) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_help(argv);
                return EXIT_SUCCESS;

            case 'm':
                if (strcmp(optarg, "uu") == 0)
                {
                    s->mode = MODE_UDP_UDP;
                }
                else if (strcmp(optarg, "ut") == 0)
                {
                    s->mode = MODE_UDP_TCP;
                }
                else if (strcmp(optarg, "tu") == 0)
                {
                    s->mode = MODE_TCP_UDP;
                }
                else if (strcmp(optarg, "ui") == 0)
                {
                    s->mode = MODE_UDP_ICMP;
                }
                else if (strcmp(optarg, "iu") == 0)
                {
                    s->mode = MODE_ICMP_UDP;
                }
                else
                {
                    fprintf(stderr, "unrecognized operating mode\n");
                    return EXIT_FAILURE;
                }
                break;

            case '4':
                s->prefer_v4 = 1;
                break;

            case 'v':
                s->verbose = 1;
                break;
            
            case 'o':
                s->obfuscate = 1;
                break;
            
            case 'p':
                s->pcap = 1;
                break;
            
            case 'l':
                localhost = optarg;
                break;

            case 'r':
                remotehost = optarg;
                break;
        }
    }

    if (remotehost != NULL)
    {
        token = strtok(remotehost, ":");
        if (resolve_host(token, &s->remote_addr, s->prefer_v4) != 0)
        {
            return EXIT_FAILURE;
        }

        token = strtok(NULL, ":");
        s->remote_port = token != NULL
            ? strtoul(token, NULL, 0)
            : 0;

        s->remote_addr.sin6_port = htons(s->remote_port);
    }
    else
    {
        fprintf(stderr, "you need to declare a remote host and port with -r\n");
        return EXIT_FAILURE;
    }

    if (localhost != NULL)
    {
        token = strtok(localhost, ":");
        if (resolve_host(token, &s->local_addr, s->prefer_v4) != 0)
        {
            return EXIT_FAILURE;
        }

        token = strtok(NULL, ":");
        s->local_port = token != NULL
            ? strtoul(token, NULL, 0)
            : 0;

        s->local_addr.sin6_port = htons(s->local_port);
    }
    else
    {
        if (s->prefer_v4)
        {
            resolve_host("127.0.0.1", &s->local_addr, 0);
        }
        else
        {
            resolve_host("::", &s->local_addr, 0);
        }

        s->local_addr.sin6_port = htons(s->local_port);
    }

    return -1;
}
