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

void print_help(char* argv[])
{
    printf("usage: %s -r addr:port [args]\narguments:\n\n", argv[0]);
    printf("   -r addr:port\tRemote host to tunnel packets to.\n");
    printf("   -l addr:port\tLocal listening address and port.\n   \t\t  Optional. Default: 127.0.0.1:8080\n");
    printf("   -o\t\tEnable generic header obfuscation.\n");
    printf("   -v\t\tDetailed logging at the expense of decreased throughput.\n");
    printf("   -h\t\tDisplays this message.\n");
}

int main(int argc, char* argv[])
{
	extern char *optarg;
	extern int optind;

    int verbose = 0, obfuscate = 0, remotebound = 0, res;
    int serverfd, remotefd;
    struct pollfd fds[2];
    char buffer[MTU_SIZE];
    char *token;
    struct hostent *localhost, *remotehost;
    struct sockaddr_in localaddr, clientaddr, remoteaddr;
    int clientaddrlen = sizeof(clientaddr), remoteaddrlen = sizeof(remoteaddr);
    int localport = 8080, remoteport = 0;

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
                verbose = 1;
                break;
            
            case 'o':
                obfuscate = 1;
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
                localport = strtoul(token, NULL, 0);

                memset(&localaddr, 0, sizeof(localaddr));
                memcpy(&localaddr.sin_addr, localhost->h_addr_list[0], localhost->h_length);
                localaddr.sin_family = AF_INET;
                localaddr.sin_port = htons(localport);
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
                remoteport = strtoul(token, NULL, 0);

                memset(&remoteaddr, 0, sizeof(remoteaddr));
                memcpy(&remoteaddr.sin_addr, remotehost->h_addr_list[0], remotehost->h_length);
                remoteaddr.sin_family = AF_INET;
                remoteaddr.sin_port = htons(remoteport);
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
        memset(&localaddr, 0, sizeof(localaddr));
        localaddr.sin_family = AF_INET;
        localaddr.sin_port = htons(localport);
        inet_pton(AF_INET, "127.0.0.1", &localaddr.sin_addr);
    }

    memset(&clientaddr, 0, sizeof(clientaddr));

    if ((serverfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    { 
        perror("server socket creation failed");
        return EXIT_FAILURE;
    }

    if ((remotefd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    { 
        perror("gateway socket creation failed");
        return EXIT_FAILURE;
    }

    if (bind(serverfd, (const struct sockaddr *)&localaddr, sizeof(localaddr)) < 0)
    {
        perror("bind failed");
        return EXIT_FAILURE;
    }

    memset(fds, 0 , sizeof(fds));
    fds[0].fd = serverfd;
    fds[0].events = POLLIN;
    fds[1].fd = remotefd;
    fds[1].events = POLLIN;

    if (obfuscate) printf("Header obfuscation enabled.\n");

    while (1)
    {
        if (!remotebound)
        {
            if (verbose) printf("Waiting for first packet from client...\n");

            socklen_t msglen = recvfrom(serverfd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&clientaddr, (unsigned int*)&clientaddrlen);

            char clientaddrstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(clientaddr.sin_addr), clientaddrstr, INET_ADDRSTRLEN);
            printf("Client connected from %s:%d\n", clientaddrstr, ntohs(clientaddr.sin_port));

            if (verbose) printf("Received %d bytes from client\n", msglen);
            if (obfuscate) obfuscate_message(buffer, msglen);

            res = sendto(remotefd, (char*)buffer, msglen, 0, (const struct sockaddr *)&remoteaddr, remoteaddrlen);

            remotebound = 1;
            continue;
        }

        if (verbose) printf("Polling...\n");

        res = poll(fds, 2, (3 * 60 * 1000));
        
        if (res == 0)
        {
            continue;
        }
        else if (res < 0)
        {
            perror("poll failed");
            return EXIT_FAILURE;
        }

        if (fds[0].revents & POLLIN)
        {
            socklen_t msglen = recvfrom(serverfd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&clientaddr, (unsigned int*)&clientaddrlen);

            if (verbose) printf("Received %d bytes from client\n", msglen);
            if (obfuscate) obfuscate_message(buffer, msglen);

            res = sendto(remotefd, (char*)buffer, msglen, 0, (const struct sockaddr *)&remoteaddr, remoteaddrlen);
        }

        if (fds[1].revents & POLLIN)
        {
            socklen_t msglen = recvfrom(remotefd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&remoteaddr, (unsigned int*)&remoteaddrlen);

            if (verbose) printf("Received %d bytes from remote\n", msglen);
            if (obfuscate) obfuscate_message(buffer, msglen);

            res = sendto(serverfd, (char*)buffer, msglen, 0, (const struct sockaddr *)&clientaddr, clientaddrlen);
        }
    }

    return 0;
}
