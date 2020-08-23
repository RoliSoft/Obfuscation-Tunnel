#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <signal.h>

#define MODE_UDP_UDP 0
#define MODE_UDP_TCP 1
#define MODE_TCP_UDP 2
#define MODE_UDP_ICMP 3
#define MODE_ICMP_UDP 4
#define MTU_SIZE 1500

#define ETHHDR_LEN 14
#define IPHDR_LEN 20
#define IPHDR_SRC_OFFSET 12
#define ICMP_LEN 8
#define ICMP_SEQ_OFFSET 6
#define ICMP_SKIP (IPHDR_LEN + ICMP_LEN)
#define PCAP_ICMP_SKIP (ETHHDR_LEN + IPHDR_LEN + ICMP_LEN)

#define min(X, Y) (((X) < (Y)) ? (X) : (Y))

static volatile sig_atomic_t run = 1;
static int sockets[10];

static void sig_handler(int _)
{
    (void)_;

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

void print_help(char* argv[])
{
    printf("usage: %s -r addr:port [args]\narguments:\n\n", argv[0]);
    printf("   -r addr:port\tRemote host to tunnel packets to.\n");
    printf("   -l addr:port\tLocal listening address and port.\n   \t\t  Optional, defaults to 127.0.0.1:8080\n");
    printf("   -m mode\tOperation mode. Possible values:\n   \t\t  uu - UDP-to-UDP (Default)\n   \t\t  ut - UDP-to-TCP\n   \t\t  tu - TCP-to-UDP\n   \t\t  ui - UDP-to-ICMP (Requires root)   \t\t  tu - ICMP-to-UDP (Requires root)\n\n");
    printf("   -p\t\tUse PCAP, only applicable to ICMP tunnels, highly recommended.\n");
    printf("   -o\t\tEnable generic header obfuscation.\n");
    printf("   -v\t\tDetailed logging at the expense of decreased throughput.\n");
    printf("   -h\t\tDisplays this message.\n");
}

int parse_arguments(int argc, char* argv[],
                    int *mode, int *verbose, int *obfuscate, int *pcap,
                    struct sockaddr_in *localaddr, int *localport,
                    struct sockaddr_in *remoteaddr, int *remoteport)
{
    char *token;
    struct hostent *localhost = NULL, *remotehost = NULL;

    if (argc == 1)
    {
        print_help(argv);
        return EXIT_SUCCESS;
    }

    int opt;
    while((opt = getopt(argc, argv, "hm:l:r:opv")) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_help(argv);
                return EXIT_SUCCESS;

            case 'm':
                if (strcmp(optarg, "uu") == 0)
                {
                    *mode = MODE_UDP_UDP;
                }
                else if (strcmp(optarg, "ut") == 0)
                {
                    *mode = MODE_UDP_TCP;
                }
                else if (strcmp(optarg, "tu") == 0)
                {
                    *mode = MODE_TCP_UDP;
                }
                else if (strcmp(optarg, "ui") == 0)
                {
                    *mode = MODE_UDP_ICMP;
                }
                else if (strcmp(optarg, "iu") == 0)
                {
                    *mode = MODE_ICMP_UDP;
                }
                else
                {
                    fprintf(stderr, "unrecognized operating mode\n");
                    return EXIT_FAILURE;
                }
                break;

            case 'v':
                *verbose = 1;
                break;
            
            case 'o':
                *obfuscate = 1;
                break;
            
            case 'p':
                *pcap = 1;
                break;
            
            case 'l':
                token = strtok(optarg, ":");
                localhost = gethostbyname(token);

                if (localhost == NULL)
                {
                    perror("failed to resolve local host");
                    return EXIT_FAILURE;
                }

                token = strtok(NULL, ":");
                if (token != NULL)
                {
                    *localport = strtoul(token, NULL, 0);
                }
                else
                {
                    *localport = 0;
                }

                memset(localaddr, 0, sizeof(*localaddr));
                memcpy(&(localaddr->sin_addr), localhost->h_addr_list[0], localhost->h_length);
                localaddr->sin_family = AF_INET;
                localaddr->sin_port = htons(*localport);
                break;

            case 'r':
                token = strtok(optarg, ":");
                remotehost = gethostbyname(token);

                if (remotehost == NULL)
                {
                    perror("failed to resolve remote host");
                    return EXIT_FAILURE;
                }

                token = strtok(NULL, ":");
                if (token != NULL)
                {
                    *remoteport = strtoul(token, NULL, 0);
                }
                else
                {
                    *remoteport = 0;
                }

                memset(remoteaddr, 0, sizeof(*remoteaddr));
                memcpy(&(remoteaddr->sin_addr), remotehost->h_addr_list[0], remotehost->h_length);
                remoteaddr->sin_family = AF_INET;
                remoteaddr->sin_port = htons(*remoteport);
                break;
        }
    }

    if (remotehost == NULL)
    {
        fprintf(stderr, "you need to declare a remote host and port with -r\n");
        return EXIT_FAILURE;
    }

    if (localhost == NULL)
    {
        memset(localaddr, 0, sizeof(*localaddr));
        localaddr->sin_family = AF_INET;
        localaddr->sin_port = htons(*localport);
        inet_pton(AF_INET, "127.0.0.1", &(localaddr->sin_addr));
    }

    return -1;
}
