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

#define PROTO_UDP 0
#define PROTO_TCP 1
#define PROTO_ICMP 2
#define PROTO_ICMP6 3
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
static std::vector<int> sockets = std::vector<int>();
#if HAVE_PCAP
static std::vector<pcap_t*> pcaps = std::vector<pcap_t*>();
#endif

struct session
{
    // boolean flags
    bool verbose;
    bool obfuscate;
    bool omit_length;
    bool random_id;
    bool no_threading;
#if HAVE_PCAP
    bool pcap;
    char *cap_dev;
#endif

    // local server configured with -l
    int local_proto;
    struct sockaddr_in local_addr;
    char __local_addr_pad[IP6_SIZE - IP_SIZE];

    // remote gateway or end server configured with -r
    int remote_proto;
    struct sockaddr_in remote_addr;
    char __remote_addr_pad[IP6_SIZE - IP_SIZE];
};

class transport_base
{
public:
    bool started = false;
    bool connected = false;
    bool verbose;

    virtual int start() = 0;
    virtual int stop() = 0;
    virtual int send(char *buffer, ssize_t msglen) = 0;
    virtual int receive(char *buffer, int* offset) = 0;
    virtual int get_selectable() { return -1; }
    virtual int restart() { return -1; }

protected:
    transport_base(bool verbose = false)
        : verbose(verbose)
    {
    }
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

    for (auto fd : sockets)
    {
        close(fd);
        shutdown(fd, SHUT_RDWR);
    }

#if HAVE_PCAP
    for (auto pcap : pcaps)
    {
        pcap_breakloop(pcap);
    }
#endif
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
        if (local->start() != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
    }
    if (!remote->started)
    {
        if (remote->start() != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
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

            if (msglen > 0)
            {
                if (obfuscate) obfuscate_message(buffer + MTU_SIZE + offset, msglen);

                remote->send(buffer + MTU_SIZE + offset, msglen);
            }
            else if (msglen < 0)
            {
                local->restart();
            }
        }

        if (fds[1].revents == POLLIN)
        {
            msglen = remote->receive(buffer + MTU_SIZE, &offset);

            if (msglen > 0)
            {
                if (obfuscate) obfuscate_message(buffer  + MTU_SIZE+ offset, msglen);

                local->send(buffer + MTU_SIZE + offset, msglen);
            }
            else if (msglen < 0)
            {
                remote->restart();
            }
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
        if (local->start() != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
    }
    if (!remote->started)
    {
        if (remote->start() != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
    }

    threads[0] = std::thread([](transport_base *local, transport_base *remote, bool obfuscate)
    {
        int msglen, offset;
        char buffer[MTU_SIZE * 3];
        while (run)
        {
            msglen = local->receive(buffer + MTU_SIZE, &offset);

            if (msglen == 0)
            {
                continue;
            }
            else if (msglen < 0)
            {
                local->restart();
                continue;
            }

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

            if (msglen == 0)
            {
                continue;
            }
            else if (msglen < 0)
            {
                remote->restart();
                continue;
            }

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
    if (inet_ntop(sockaddr->sin6_family, &sockaddr->sin6_addr, (char*)&addrstr, sizeof(addrstr)) == NULL)
    {
        return;
    }

    printf("%s", addrstr);
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
    printf("   -o\t\tEnable generic header obfuscation.\n");
    printf("   -s\t\tDisable multithreading, multiplex sockets instead.\n");
    printf("   -v\t\tDetailed logging at the expense of decreased throughput.\n");
    printf("   -h\t\tDisplays this message.\n");
    printf("\nTCP-specific arguments:\n\n");
    printf("   -n\t\tDo not send and expect 7-bit encoded length header.\n");
    printf("\nICMP-specific arguments:\n\n");
#if HAVE_PCAP
    printf("   -p [if]\tUse PCAP for inbound, highly recommended.\n   \t\t  Optional value, defaults to default gateway otherwise.\n");
#endif
    printf("   -x\t\tExpect identifier and sequence randomization.\n   \t\t  Not recommended, see documentation for pros and cons.\n");
}

int parse_protocol_tag(char *tag)
{
    for (char *c = tag; *c; c++)
    {
        *c = tolower(*c);
    }

    if (strcmp(tag, "udp") == 0)
    {
        return PROTO_UDP;
    }
    else if (strcmp(tag, "tcp") == 0)
    {
        return PROTO_TCP;
    }
    else if (strcmp(tag, "icmp") == 0)
    {
        return PROTO_ICMP;
    }
    else if (strcmp(tag, "icmp6") == 0)
    {
        return PROTO_ICMP6;
    }
    else
    {
        fprintf(stderr, "'%s' is not a supported protocol.\n", tag);
        return -1;
    }
}

int parse_endpoint_arg(char* argument, int *proto_dest, struct sockaddr_in *addr_dest)
{
    char* token = strtok(argument, ":");
    int proto = parse_protocol_tag(token);

    if (proto == -1)
    {
        return EXIT_FAILURE;
    }

    *proto_dest = proto;
    
    token = strtok(NULL, ":");

    bool is_v6 = false;
    char addr6str[INET6_ADDRSTRLEN];
    if (token[0] == '[')
    {
        // parse ipv6 between [] with strtok on :

        for (char *src = &token[1], *dst = (char*)&addr6str;;)
        {
            if (*src == ']')
            {
                *dst = 0;
                is_v6 = true;
                break;
            }
            else if (*src == 0)
            {
                token = strtok(NULL, ":");
                if (token == NULL) break;

                if (token[-2] == 0)
                {
                    // detect two colons
                    *dst++ = ':';
                }

                if (token[0] == ']')
                {
                    // detect end without number
                    *dst++ = ':';
                    *dst = 0;
                    is_v6 = true;
                    break;
                }

                src = token;
                *dst++ = ':';
            }

            *dst++ = *src++;
        }

        if (!is_v6)
        {
            fprintf(stderr, "Could not parse IPv6 address.\n");
            return EXIT_FAILURE;
        }
    }

    if (proto == PROTO_ICMP6 || is_v6)
    {
        if (resolve_host6(is_v6 ? addr6str : token, (struct sockaddr_in6*)addr_dest) != 0)
        {
            return EXIT_FAILURE;
        }
    }
    else
    {
        if (resolve_host(token, addr_dest) != 0)
        {
            return EXIT_FAILURE;
        }
    }

    token = strtok(NULL, ":");
    int port = token != NULL
        ? strtoul(token, NULL, 0)
        : 0;

    if (port != 0)
    {
        addr_dest->sin_port = htons(port);
    }

    return EXIT_SUCCESS;
}

int parse_arguments(int argc, char* argv[], struct session *s)
{
    char *localhost = NULL, *remotehost = NULL;

    if (argc == 1)
    {
        print_help(argv);
        return EXIT_SUCCESS;
    }

    memset(s, 0, sizeof(*s));

    int opt;
    while((opt = getopt(argc, argv, ":hl:r:op:svnx")) != -1)
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

            case 'v':
                s->verbose = true;
                break;
            
            case 's':
                s->no_threading = true;
                break;
            
            case 'o':
                s->obfuscate = true;
                break;
            
            case 'x':
                s->random_id = true;
                break;
            
            case 'n':
                s->omit_length = true;
                break;
            
            case 'p':
#if HAVE_PCAP
                s->pcap = true;

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

    if (localhost == NULL || remotehost == NULL)
    {
        fprintf(stderr, "You need to declare a local and remote endpoint with -l and -r.\n");
        return EXIT_FAILURE;
    }

    if (parse_endpoint_arg(remotehost, &s->remote_proto, &s->remote_addr) != EXIT_SUCCESS)
    {
        return EXIT_FAILURE;
    }

    if (parse_endpoint_arg(localhost, &s->local_proto, &s->local_addr) != EXIT_SUCCESS)
    {
        return EXIT_FAILURE;
    }

    return -1;
}
