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
#include <pthread.h>
#include <errno.h>
#include <vector>
#include <thread>

#ifdef AF_PACKET
    // Linux
    #include <linux/filter.h>
#endif

#ifndef HAVE_PCAP
    #define HAVE_PCAP 1
#endif

#if HAVE_PCAP
    #include <pcap/pcap.h>
#endif

#define MODE_UDP_UDP 0
#define MODE_UDP_TCP 1
#define MODE_TCP_UDP 2
#define MODE_UDP_ICMP 3
#define MODE_ICMP_UDP 4
#define MODE_UDP_ICMP6 5
#define MODE_ICMP6_UDP 6
#define MTU_SIZE 1500

#define IP_SIZE sizeof(struct sockaddr_in)
#define IP6_SIZE sizeof(struct sockaddr_in6)
#define ETHHDR_LEN 14
#define IPHDR_LEN 20
#define IPHDR_SRC_OFFSET 12
#define IP6HDR_LEN 40
#define IP6HDR_SRC_OFFSET 8
#define ICMP_LEN 8
#define ICMP_ID_OFFSET 4
#define ICMP_SEQ_OFFSET 6
#define ICMP_SKIP (IPHDR_LEN + ICMP_LEN)
#define ICMP6_SKIP ICMP_LEN
#define PCAP_ICMP_SKIP (ETHHDR_LEN + IPHDR_LEN + ICMP_LEN)
#define PCAP_ICMP6_SKIP (ETHHDR_LEN + IP6HDR_LEN + ICMP_LEN)

#define min(X, Y) (((X) < (Y)) ? (X) : (Y))
#define max(X, Y) (((X) > (Y)) ? (X) : (Y))
#define if_optional_arg() if (optarg && optarg[0] == '-') { optind--; continue; } else if (optarg)

static volatile sig_atomic_t run = 1;
static int sockets[10];
static std::vector<int> sockets2 = std::vector<int>();

struct session
{
    // boolean flags
    int mode;
    int verbose;
    int obfuscate;
#if HAVE_PCAP
    int pcap;
#endif

    // local server configured with -l
    struct sockaddr_in local_addr;
    char __local_addr_pad[IP6_SIZE - IP_SIZE];
    int local_port;
    int server_fd;

    // remote gateway or end server configured with -r
    struct sockaddr_in remote_addr;
    char __remote_addr_pad[IP6_SIZE - IP_SIZE];
    int remote_port;
    int remote_fd;

    // address of the connecting client to local server
    struct sockaddr_in client_addr;
    char __client_addr_pad[IP6_SIZE - IP_SIZE];
    int client_fd;

    // protocol-dependent stateful variables
    int connected;
    unsigned short identifier;
    unsigned short sequence;
    int random_id;

#if HAVE_PCAP
    pcap_t *cap_ptr;
    char *cap_dev;
#endif
};

class transport_base
{
public:
    bool started = false;
    bool connected = false;
    bool verbose = false;

    virtual int start() = 0;
    virtual int stop() = 0;
    virtual int send(char *buffer, ssize_t msglen) = 0;
    virtual int receive(char *buffer, int* offset) = 0;
    virtual int get_selectable() { return -1; };
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

    for (auto fd : sockets2)
    {
        close(fd);
        shutdown(fd, SHUT_RDWR);
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

int loop_transports_select(transport_base *local, transport_base *remote, bool obfuscate)
{
    struct pollfd fds[2];
    memset(fds, 0 , sizeof(fds));

    if (!local->started)
    {
        local->start();
    }
    if (!remote->started)
    {
        remote->start();
    }

    fds[0].fd = local->get_selectable();
    fds[0].events = POLLIN;
    fds[1].fd = remote->get_selectable();
    fds[1].events = POLLIN;

    int msglen, offset;
    char buffer[MTU_SIZE * 3];
    while (run)
    {
        msglen = poll(fds, 2, 3 * 60 * 1000);

        if (fds[0].revents == POLLIN)
        {
            msglen = local->receive(buffer + MTU_SIZE, &offset);

            if (obfuscate) obfuscate_message(buffer + MTU_SIZE + offset, msglen);

            remote->send(buffer + MTU_SIZE + offset, msglen);
        }

        if (fds[1].revents == POLLIN)
        {
            msglen = remote->receive(buffer + MTU_SIZE, &offset);

            if (obfuscate) obfuscate_message(buffer  + MTU_SIZE+ offset, msglen);

            local->send(buffer + MTU_SIZE + offset, msglen);
        }
    }

    local->stop();
    remote->stop();

    return run ? EXIT_FAILURE : EXIT_SUCCESS;
}

int loop_transports_thread(transport_base *local, transport_base *remote, bool obfuscate)
{
    std::thread threads[2];

    if (!local->started)
    {
        local->start();
    }
    if (!remote->started)
    {
        remote->start();
    }

    threads[0] = std::thread([](transport_base *local, transport_base *remote, bool obfuscate)
    {
        int msglen, offset;
        char buffer[MTU_SIZE * 3];
        while (run)
        {
            msglen = local->receive(buffer + MTU_SIZE, &offset);

            if (obfuscate) obfuscate_message(buffer + MTU_SIZE + offset, msglen);

            remote->send(buffer + MTU_SIZE + offset, msglen);
        }
    }, std::cref(local), std::cref(remote), std::cref(obfuscate));

    threads[1] = std::thread([](transport_base *local, transport_base *remote, bool obfuscate)
    {
        int msglen, offset;
        char buffer[MTU_SIZE * 3];
        while (run)
        {
            msglen = remote->receive(buffer + MTU_SIZE, &offset);

            if (obfuscate) obfuscate_message(buffer + MTU_SIZE + offset, msglen);

            local->send(buffer + MTU_SIZE + offset, msglen);
        }
    }, std::cref(local), std::cref(remote), std::cref(obfuscate));

    for (int i = 0; i < 2; i++)
    {
        threads[i].join();  
    }

    local->stop();
    remote->stop();

    return run ? EXIT_FAILURE : EXIT_SUCCESS;
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

void print_ip(struct sockaddr_in *sockaddr)
{
    if (sockaddr->sin_family != AF_INET)
    {
        return;
    }

    char addrstr[INET_ADDRSTRLEN];
    if (inet_ntop(sockaddr->sin_family, &sockaddr->sin_addr, (char*)&addrstr, sizeof(*sockaddr)) == NULL)
    {
        return;
    }

    printf("%s", addrstr);
}

void print_ip_port(struct sockaddr_in *sockaddr)
{
    if (sockaddr->sin_family != AF_INET)
    {
        return;
    }

    print_ip(sockaddr);
    printf(":%d", ntohs(sockaddr->sin_port));
}

void print_ip6(struct sockaddr_in6 *sockaddr)
{
    if (sockaddr->sin6_family != AF_INET6)
    {
        return;
    }

    char addrstr[INET6_ADDRSTRLEN];
    if (inet_ntop(sockaddr->sin6_family, &sockaddr->sin6_addr, (char*)&addrstr, sizeof(*sockaddr)) == NULL)
    {
        return;
    }

    printf("%s", addrstr);
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

int resolve_host(const char *addr, struct sockaddr_in *sockaddr)
{
    int res;
    struct addrinfo hints, *addrs;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_ALL;

    if ((res = getaddrinfo(addr, NULL, &hints, &addrs)) != 0)
    {
        fprintf(stderr, "Failed to resolve host %s: %s\n", addr, gai_strerror(res));
        return res;
    }

    memset(sockaddr, 0, sizeof(*sockaddr));
    memcpy(sockaddr, addrs->ai_addr, addrs->ai_addrlen);
    freeaddrinfo(addrs);

    return res;
}

int resolve_host6(const char *addr, struct sockaddr_in6 *sockaddr)
{
    int res;
    struct addrinfo hints, *addrs;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_ALL;

    if ((res = getaddrinfo(addr, NULL, &hints, &addrs)) != 0)
    {
        fprintf(stderr, "Failed to resolve host %s: %s\n", addr, gai_strerror(res));
        return res;
    }

    memset(sockaddr, 0, sizeof(*sockaddr));
    memcpy(sockaddr, addrs->ai_addr, addrs->ai_addrlen);
    freeaddrinfo(addrs);

    return res;
}

void print_help(char* argv[])
{
    printf("usage: %s -r addr:port [args]\narguments:\n\n", argv[0]);
    printf("   -r addr:port\tRemote host to tunnel packets to.\n");
    printf("   -l addr:port\tLocal listening address and port.\n   \t\t  Optional, defaults to 127.0.0.1:8080\n");
    printf("   -m mode\tOperation mode. Possible values:\n   \t\t  uu - UDP-to-UDP (Default)\n   \t\t  ut - UDP-to-TCP\n   \t\t  tu - TCP-to-UDP\n   \t\t  ui - UDP-to-ICMP (Requires root)\n   \t\t  iu - ICMP-to-UDP (Requires root)\n   \t\t  ui6 - UDP-to-ICMPv6 (Requires root)\n   \t\t  i6u - ICMPv6-to-UDP (Requires root)\n");
    printf("   -o\t\tEnable generic header obfuscation.\n");
    printf("   -v\t\tDetailed logging at the expense of decreased throughput.\n");
    printf("   -h\t\tDisplays this message.\n");
    printf("\nICMP-specific arguments:\n\n");
#if HAVE_PCAP
    printf("   -p [if]\tUse PCAP for inbound, highly recommended.\n   \t\t  Optional value, defaults to default gateway otherwise.\n");
#endif
    printf("   -x\t\tExpect identifier and sequence randomization.\n   \t\t  Not recommended, see documentation for pros and cons.\n");
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
    while((opt = getopt(argc, argv, ":hm:l:r:op:vx")) != -1)
    {
        if (opt == ':' && optopt != opt)
        {
            opt = optopt;
        }

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
                else if (strcmp(optarg, "ui6") == 0)
                {
                    s->mode = MODE_UDP_ICMP6;
                }
                else if (strcmp(optarg, "i6u") == 0)
                {
                    s->mode = MODE_ICMP6_UDP;
                }
                else
                {
                    fprintf(stderr, "Unrecognized operating mode in flag -m.\n");
                    return EXIT_FAILURE;
                }
                break;

            case 'v':
                s->verbose = 1;
                break;
            
            case 'o':
                s->obfuscate = 1;
                break;
            
            case 'x':
                s->random_id = 1;
                break;
            
            case 'p':
#if HAVE_PCAP
                s->pcap = 1;

                if_optional_arg()
                {
                    s->cap_dev = optarg;
                }
                break;
#else
                fprintf(stderr, "This version was not compiled with PCAP support.\n");
                return EXIT_FAILURE;
#endif
            
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
        if (s->mode == MODE_UDP_ICMP6)
        {
            if (resolve_host6(remotehost, (struct sockaddr_in6*)&s->remote_addr) != 0)
            {
                return EXIT_FAILURE;
            }
        }
        else
        {
            token = strtok(remotehost, ":");
            if (resolve_host(token, &s->remote_addr) != 0)
            {
                return EXIT_FAILURE;
            }

            token = strtok(NULL, ":");
            s->remote_port = token != NULL
                ? strtoul(token, NULL, 0)
                : 0;

            s->remote_addr.sin_port = htons(s->remote_port);
        }
    }
    else
    {
        fprintf(stderr, "You need to declare a remote host and port with -r.\n");
        return EXIT_FAILURE;
    }

    if (localhost != NULL)
    {
        if (s->mode == MODE_ICMP6_UDP)
        {
            if (resolve_host6(localhost, (struct sockaddr_in6*)&s->local_addr) != 0)
            {
                return EXIT_FAILURE;
            }
        }
        else
        {
            token = strtok(localhost, ":");
            if (resolve_host(token, &s->local_addr) != 0)
            {
                return EXIT_FAILURE;
            }

            token = strtok(NULL, ":");
            s->local_port = token != NULL
                ? strtoul(token, NULL, 0)
                : 0;

            s->local_addr.sin_port = htons(s->local_port);
        }
    }
    else
    {
        switch (s->mode)
        {
            case MODE_ICMP_UDP:
                resolve_host("0.0.0.0", &s->local_addr);
                break;
            
            case MODE_ICMP6_UDP:
                resolve_host6("::", (struct sockaddr_in6*)&s->local_addr);
                break;
            
            default:
                resolve_host("127.0.0.1", &s->local_addr);
                break;
        }

        s->local_addr.sin_port = htons(s->local_port);
    }

    return -1;
}
