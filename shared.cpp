#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
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
#include <getopt.h>
#include <vector>
#include <thread>

#ifdef AF_PACKET
    // Linux
    #include <linux/filter.h>
#endif

#ifndef HAVE_PCAP
    #define HAVE_PCAP 1
#endif
#ifndef HAVE_TLS
    #define HAVE_TLS 1
#endif

#if HAVE_PCAP
    #include <pcap/pcap.h>
#endif

#define PROTO_UDP 0
#define PROTO_TCP 1
#define PROTO_TLS 2
#define PROTO_DTLS 3
#define PROTO_ICMP 4
#define PROTO_ICMP6 5
#define LENGTH_VAR 0
#define LENGTH_16BIT 1
#define LENGTH_NONE 2
#define STD_MTU_SIZE 1500
#define MTU_SIZE USHRT_MAX

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

#define TLS_DEFAULT_CN "localhost"

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
    int length_type;
    bool random_id;
    bool no_threading;
    char *obfuscator;
    char *key;
    int key_length;
    char *mocker;
    bool fragment;
    char *domain;
#if HAVE_PCAP
    bool pcap;
    char *cap_dev;
#endif
#if HAVE_TLS
    bool tls_no_verify;
    char *tls_ca_bundle;
    char *tls_cert_file;
    char *tls_key_file;
#endif

    // local server configured with -l
    int local_proto;
    char *local_host;
    struct sockaddr_in local_addr;
    char __local_addr_pad[IP6_SIZE - IP_SIZE];

    // remote gateway or end server configured with -r
    int remote_proto;
    char *remote_host;
    struct sockaddr_in remote_addr;
    char __remote_addr_pad[IP6_SIZE - IP_SIZE];
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
    printf("usage: %s -l proto:addr:port -r proto:addr:port [args]\narguments:\n\n", argv[0]);
    printf("   -l endpoint\tLocal listening protocol, address and port.\n   \t\t  Example: tcp:127.0.0.1:80 / icmp6:[::1]\n   \t\t  Supported protocols: udp, dtls, tcp, tls, icmp, imcp6.\n");
    printf("   -r endpoint\tRemote host to tunnel packets to.\n");
    printf("   -o [mode]\tEnable packet obfuscation. Possible values:\n   \t\t  header - Simple generic header obfuscation (Default)\n   \t\t  xor - XOR packet obfuscation with rolling key\n");
    printf("   -k key\tSpecifies a key for the obfuscator module.\n");
    printf("   -m mode\tEnable protocol imitator. Possible values:\n   \t\t  dns_client - Send data as A queries to remote\n   \t\t  dns_server - Reply to A queries on local\n   \t\t  http_ws_client - Masquarade as HTTP WebSocket stream\n   \t\t  http_ws_server - Accept data in HTTP WebSocket streams\n");
    printf("   -s\t\tDisable multithreading, multiplex sockets instead.\n");
    printf("   -v\t\tDetailed logging at the expense of decreased throughput.\n");
    printf("   -h, --help\tDisplays this message.\n");
    printf("\nTCP-specific arguments:\n\n");
    printf("   -e\t\tType of encoding to use for the length header:\n   \t\t  v - 7-bit encoded variable-length header (Default)\n   \t\t  s - 2-byte unsigned short\n   \t\t  n - None (Not recommended)\n");
    printf("\nICMP/ICMPv6-specific arguments:\n\n");
#if HAVE_PCAP
    printf("   -p [if]\tUse PCAP for inbound, highly recommended.\n   \t\t  Optional value, defaults to default gateway otherwise.\n");
#endif
    printf("   -x\t\tExpect identifier and sequence randomization.\n   \t\t  Not recommended, see documentation for pros and cons.\n");
    printf("\nDNS-specific arguments:\n\n");
    printf("   -f\t\tBase32-encode data and fragment labels on 60-byte boundaries.\n");
    printf("   -d domain\tOptional domain name to act as the authoritative resolver for.\n");
    printf("\n(D)TLS-specific arguments:\n\n");
    printf("   --tls-no-verify  Ignore certificate validation errors of remote server.\n");
    printf("   --tls-ca-bundle  Path to CA bundle, if not found automatically by OpenSSL.\n");
    printf("   --tls-cert\t    Path to SSL certificate file in PEM format.\n   \t\t      Optional, otherwise it will be auto-generated and self-signed.\n");
    printf("   --tls-key\t    Path to SSL private key file in PEM format.\n");
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
    else if (strcmp(tag, "tls") == 0)
    {
        return PROTO_TLS;
    }
    else if (strcmp(tag, "dtls") == 0)
    {
        return PROTO_DTLS;
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

int parse_endpoint_arg(char* argument, int *proto_dest, char **host, struct sockaddr_in *addr_dest)
{
    char* token = strtok(argument, ":");
    if (token == NULL) return EXIT_FAILURE;

    int proto = parse_protocol_tag(token);

    if (proto == -1)
    {
        return EXIT_FAILURE;
    }

    *proto_dest = proto;
    
    token = strtok(NULL, ":");
    if (token == NULL) return EXIT_FAILURE;

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
        *host = (char*)malloc(strlen(addr6str) + 1);
        strcpy(*host, addr6str);

        if (resolve_host6(is_v6 ? addr6str : token, (struct sockaddr_in6*)addr_dest) != 0)
        {
            return EXIT_FAILURE;
        }
    }
    else
    {
        *host = (char*)malloc(strlen(token) + 1);
        strcpy(*host, token);

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
    if (argc == 1)
    {
        print_help(argv);
        return EXIT_SUCCESS;
    }

    char *localhost = NULL, *remotehost = NULL;
    memset(s, 0, sizeof(*s));

    static struct option long_options[] = {
        { "tls-ca-bundle",   required_argument, 0,  0  },
        { "tls-no-verify",   no_argument,       0,  0  },
        { "tls-cert",        required_argument, 0,  0  },
        { "tls-key",         required_argument, 0,  0  },
        { "help",            required_argument, 0, 'h' },
        { 0,                 0,                 0,  0  }
    };

    int opt, opt_idx = 0;
    while((opt = getopt_long(argc, argv, ":hl:r:o:p:sk:m:ve:xfd:", long_options, &opt_idx)) != -1)
    {
        if (opt == ':' && optopt != opt)
        {
            opt = optopt;
        }

        switch (opt)
        {
            case 0:
                if (strcmp(long_options[opt_idx].name, "tls-ca-bundle") == 0)
                {
                    s->tls_ca_bundle = optarg;
                }
                else if (strcmp(long_options[opt_idx].name, "tls-no-verify") == 0)
                {
                    s->tls_no_verify = true;
                }
                else if (strcmp(long_options[opt_idx].name, "tls-cert") == 0)
                {
                    s->tls_cert_file = optarg;
                }
                else if (strcmp(long_options[opt_idx].name, "tls-key") == 0)
                {
                    s->tls_key_file = optarg;
                }
                break;

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
                s->obfuscator = (char*)"header";

                if_optional_arg()
                {
                    s->obfuscator = optarg;
                }
                break;
            
            case 'x':
                s->random_id = true;
                break;
            
            case 'e':
                switch (optarg[0])
                {
                    case 'v':
                        s->length_type = LENGTH_VAR;
                        break;

                    case 's':
                        s->length_type = LENGTH_16BIT;
                        break;

                    case 'n':
                        s->length_type = LENGTH_NONE;
                        break;

                    default:
                        fprintf(stderr, "'%s' is not a supported length encoding.\n", optarg);
                        return EXIT_FAILURE;
                }
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

            case 'k':
                s->key = optarg;
                s->key_length = strlen(optarg);
                break;

            case 'm':
                s->mocker = optarg;
                break;

            case 'f':
                s->fragment = true;
                break;

            case 'd':
                s->domain = optarg;
                break;
        }
    }

    if (localhost == NULL || remotehost == NULL)
    {
        fprintf(stderr, "You need to declare a local and remote endpoint with -l and -r.\n");
        return EXIT_FAILURE;
    }

    if (parse_endpoint_arg(remotehost, &s->remote_proto, &s->remote_host, &s->remote_addr) != EXIT_SUCCESS)
    {
        fprintf(stderr, "Failed to parse remote endpoint.\n");
        return EXIT_FAILURE;
    }

    if (parse_endpoint_arg(localhost, &s->local_proto, &s->local_host, &s->local_addr) != EXIT_SUCCESS)
    {
        fprintf(stderr, "Failed to parse local endpoint.\n");
        return EXIT_FAILURE;
    }

    return -1;
}
