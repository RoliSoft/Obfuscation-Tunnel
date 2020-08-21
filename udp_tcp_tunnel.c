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

#define LOCAL_ADDR "0.0.0.0"
#define LOCAL_PORT 8080
#define REMOTE_ADDR "rolisoft.go.ro"
#define REMOTE_PORT 8080
//#define REMOTE_ADDR "engage.cloudflareclient.com"
//#define REMOTE_PORT 2408
//#define REMOTE_ADDR "127.0.0.1"
//#define REMOTE_PORT 8081
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

int main()
{
    int verbose = 1, obfuscate = 1, remotebound = 0, res;
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

    if ((remotefd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
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

    struct hostent* remotehost = gethostbyname(REMOTE_ADDR);

    if (remotehost == NULL)
    {
        perror("failed to resolve remote host");
        return EXIT_FAILURE;
    }

    memcpy(&remoteaddr.sin_addr, remotehost->h_addr_list[0], remotehost->h_length);
    remoteaddr.sin_family = AF_INET;
    remoteaddr.sin_port = htons(REMOTE_PORT);

    if (bind(serverfd, (const struct sockaddr *)&localaddr, sizeof(localaddr)) < 0)
    {
        perror("bind failed");
        return EXIT_FAILURE;
    }

    printf("Connecting to remote server...\n");

    if ((res = connect(remotefd, (const struct sockaddr *)&remoteaddr, remoteaddrlen)) != 0)
    {
        perror("failed to connect to remote host");
        return EXIT_FAILURE;
    }

    memset(fds, 0 , sizeof(fds));
    fds[0].fd = serverfd;
    fds[0].events = POLLIN;
    fds[1].fd = remotefd;
    fds[1].events = POLLIN;

    /*int i = 1;
    setsockopt(serverfd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
#ifdef TCP_QUICKACK
    setsockopt(serverfd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
#endif*/

    fcntl(remotefd, F_SETFL, O_NONBLOCK);

    if (obfuscate) printf("Header obfuscation enabled.\n");

    while (1)
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

        if (fds[1].revents & POLLHUP || fds[1].revents & POLLERR)
        {
            printf("TCP connection to remote lost\n");
            return EXIT_FAILURE;
        }

        if (fds[0].revents & POLLIN)
        {
            // udp -> tcp

            socklen_t msglen = recvfrom(serverfd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&clientaddr, (unsigned int*)&clientaddrlen);

            if (verbose) printf("Received %d bytes from client\n", msglen);
            if (obfuscate) obfuscate_message(buffer, msglen);

            res = write(remotefd, (char*)buffer, msglen);
        }

        if (fds[1].revents & POLLIN)
        {
            // tcp -> udp

            socklen_t msglen = read(remotefd, (char*)buffer, MTU_SIZE);

            if (verbose) printf("Received %d bytes from remote\n", msglen);
            if (obfuscate) obfuscate_message(buffer, msglen);

            res = sendto(serverfd, (char*)buffer, msglen, 0, (const struct sockaddr *)&clientaddr, clientaddrlen);
        }
    }

    close(remotefd);

    return 0;
}