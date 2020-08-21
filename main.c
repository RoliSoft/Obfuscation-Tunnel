#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define LOCAL_ADDR "0.0.0.0"
#define LOCAL_PORT 8080
#define REMOTE_ADDR "5.15.36.143"
#define REMOTE_PORT 8080
//#define REMOTE_ADDR "162.159.192.1"
//#define REMOTE_PORT 2408
#define MTU_SIZE 1500

#define min(X, Y) (((X) < (Y)) ? (X) : (Y))

static inline void obfuscate(char* message, int length)
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

int main()
{
    int verbose = 0, remotebound = 0, res;
    int serverfd, remotefd;
    struct pollfd fds[2];
    char buffer[MTU_SIZE];
    struct sockaddr_in localaddr, clientaddr, remoteaddr;
    int clientaddrlen = sizeof(clientaddr), remoteaddrlen = sizeof(remoteaddr);

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

    memset(&localaddr, 0, sizeof(localaddr));
    memset(&clientaddr, 0, sizeof(clientaddr));
    memset(&remoteaddr, 0, sizeof(remoteaddr));

    localaddr.sin_family = AF_INET;
    localaddr.sin_port = htons(LOCAL_PORT);
    inet_pton(AF_INET, LOCAL_ADDR, &localaddr.sin_addr);

    remoteaddr.sin_family = AF_INET;
    remoteaddr.sin_port = htons(REMOTE_PORT);
    inet_pton(AF_INET, REMOTE_ADDR, &remoteaddr.sin_addr);

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

    while (1)
    {
        if (!remotebound)
        {
            if (verbose) printf("Waiting for first packet from client...\n");

            socklen_t msglen = recvfrom(serverfd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&clientaddr, (unsigned int*)&clientaddrlen);
            if (verbose) printf("Received %d bytes from client\n", msglen);

            obfuscate(buffer, msglen);

            res = sendto(remotefd, (char*)buffer, msglen, 0, (const struct sockaddr *)&remoteaddr, remoteaddrlen);

            remotebound = 1;
        }
        else
        {
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

            if (fds[1].revents == POLLIN)
            {
                socklen_t msglen = recvfrom(remotefd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&remoteaddr, (unsigned int*)&remoteaddrlen);
                if (verbose) printf("Received %d bytes from remote\n", msglen);

                obfuscate(buffer, msglen);

                res = sendto(serverfd, (char*)buffer, msglen, 0, (const struct sockaddr *)&clientaddr, clientaddrlen);
            }

            if (fds[0].revents == POLLIN)
            {
                socklen_t msglen = recvfrom(serverfd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&clientaddr, (unsigned int*)&clientaddrlen);
                if (verbose) printf("Received %d bytes from client\n", msglen);

                obfuscate(buffer, msglen);

                res = sendto(remotefd, (char*)buffer, msglen, 0, (const struct sockaddr *)&remoteaddr, remoteaddrlen);
            }
        }
    }

    return 0;
}