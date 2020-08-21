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
//#define REMOTE_ADDR "rolisoft.go.ro"
//#define REMOTE_PORT 8080
//#define REMOTE_ADDR "engage.cloudflareclient.com"
//#define REMOTE_PORT 2408
#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT 8081
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
    int verbose = 0, obfuscate = 1, remotebound = 0, res;
    int serverfd, remotefd, clientfd;
    struct pollfd fds[2];
    char buffer[MTU_SIZE];
    struct sockaddr_in localaddr, clientaddr, remoteaddr;
    int clientaddrlen = sizeof(clientaddr), remoteaddrlen = sizeof(remoteaddr);

    if ((serverfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
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

    if ((res = listen(serverfd, 1)) != 0)
    {
        perror("failed to listen on local port");
        return EXIT_FAILURE;
    }

    printf("Waiting for first client...\n");

    clientfd = accept(serverfd, (struct sockaddr*)&clientaddr, (unsigned int*)&clientaddrlen);

    if (clientfd < 0)
    {
        perror("failed to accept incoming connection");
        return EXIT_FAILURE;
    }

    char clientaddrstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(clientaddr.sin_addr), clientaddrstr, INET_ADDRSTRLEN);
    printf("Client connected from %s:%d\n", clientaddrstr, ntohs(clientaddr.sin_port));

    if (obfuscate) printf("Header obfuscation enabled.\n");

    memset(fds, 0 , sizeof(fds));
    fds[0].fd = clientfd;
    fds[0].events = POLLIN;
    fds[1].fd = remotefd;
    fds[1].events = POLLIN;

    int i = 1;
    setsockopt(clientfd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
#ifdef TCP_QUICKACK
    setsockopt(clientfd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
#endif

    //fcntl(clientfd, F_SETFL, O_NONBLOCK);

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

        if (fds[0].revents & POLLHUP || fds[0].revents & POLLERR)
        {
            printf("TCP connection to client lost\n");
            return EXIT_FAILURE;
        }

        if (fds[0].revents & POLLIN)
        {
            // tcp -> udp

            socklen_t msglen = read(clientfd, (char*)buffer, sizeof(unsigned short));

            if (msglen == 0)
            {
                printf("TCP connection to client lost\n");
                return EXIT_FAILURE;
            }

            if (msglen != sizeof(unsigned short))
            {
                printf("Warning: read %d instead of %lu.\n", msglen, sizeof(unsigned short));
                continue;
            }

            unsigned short toread = 0;
            ((unsigned char*)&toread)[0] = buffer[0];
            ((unsigned char*)&toread)[1] = buffer[1];
            toread = ntohs(toread);

            if (toread > MTU_SIZE)
            {
                printf("Incorrect size read from buffer, abandoning read.\n");
                continue;
            }

            unsigned short readsize = toread;

            while (toread > 0)
            {
                msglen = read(clientfd, (char*)buffer + (readsize - toread), toread);

                if (verbose && toread != msglen)
                {
                    printf("Read partially, need %u more bytes.\n", toread - msglen);
                }

                toread -= msglen;
            }

            if (verbose) printf("Received %d bytes from client\n", msglen);
            if (obfuscate) obfuscate_message(buffer, readsize);

            res = sendto(remotefd, (char*)buffer, readsize, 0, (const struct sockaddr *)&remoteaddr, remoteaddrlen);
        }

        if (fds[1].revents & POLLIN)
        {
            // udp -> tcp

            socklen_t msglen = recvfrom(remotefd, ((char*)buffer) + sizeof(unsigned short), MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&remoteaddr, (unsigned int*)&remoteaddrlen);

            if (verbose) printf("Received %d bytes from remote\n", msglen);
            if (obfuscate) obfuscate_message(((char*)buffer) + sizeof(unsigned short), msglen);

            unsigned short wirelen = htons(msglen);
            
            buffer[0] = ((unsigned char*)&wirelen)[0];
            buffer[1] = ((unsigned char*)&wirelen)[1];

            res = write(clientfd, (char*)buffer, msglen + sizeof(unsigned short));
        }
    }

    close(remotefd);

    return 0;
}