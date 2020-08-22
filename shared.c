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

#define MTU_SIZE 1500
#define min(X, Y) (((X) < (Y)) ? (X) : (Y))

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

void print_help(char* argv[])
{
    printf("usage: %s -r addr:port [args]\narguments:\n\n", argv[0]);
    printf("   -r addr:port\tRemote host to tunnel packets to.\n");
    printf("   -l addr:port\tLocal listening address and port.\n   \t\t  Optional. Default: 127.0.0.1:8080\n");
    printf("   -o\t\tEnable generic header obfuscation.\n");
    printf("   -v\t\tDetailed logging at the expense of decreased throughput.\n");
    printf("   -h\t\tDisplays this message.\n");
}

int parse_arguments(int argc, char* argv[],
                    int *verbose, int *obfuscate,
                    struct hostent *localhost, struct hostent *remotehost,
                    int *localport, int *remoteport,
                    struct sockaddr_in *localaddr, struct sockaddr_in *clientaddr, struct sockaddr_in *remoteaddr)
{
    char *token;

    if (argc == 1)
    {
        print_help(argv);
        return EXIT_SUCCESS;
    }

    int opt;
    while((opt = getopt(argc, argv, "hl:r:ov")) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_help(argv);
                return EXIT_SUCCESS;

            case 'v':
                *verbose = 1;
                break;
            
            case 'o':
                *obfuscate = 1;
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
                *localport = strtoul(token, NULL, 0);

                memset(localaddr, 0, sizeof(*localaddr));
                memcpy(&localaddr->sin_addr, localhost->h_addr_list[0], localhost->h_length);
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
                *remoteport = strtoul(token, NULL, 0);

                memset(remoteaddr, 0, sizeof(*remoteaddr));
                memcpy(&remoteaddr->sin_addr, remotehost->h_addr_list[0], remotehost->h_length);
                remoteaddr->sin_family = AF_INET;
                remoteaddr->sin_port = htons(*remoteport);
                break;
        }
    }

    if (remotehost == NULL)
    {
        fprintf(stderr, "%s: you need to declare a remote host and port with -r\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (localhost == NULL)
    {
        memset(localaddr, 0, sizeof(*localaddr));
        localaddr->sin_family = AF_INET;
        localaddr->sin_port = htons(*localport);
        inet_pton(AF_INET, "127.0.0.1", &localaddr->sin_addr);
    }

    memset(clientaddr, 0, sizeof(*clientaddr));

    return -1;
}