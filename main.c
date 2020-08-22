#include "shared.c"

int main(int argc, char* argv[])
{
    int verbose = 0, obfuscate = 0, remotebound = 0, res;
    int serverfd, remotefd;
    struct pollfd fds[2];
    char buffer[MTU_SIZE];
    struct hostent *localhost, *remotehost;
    struct sockaddr_in localaddr, clientaddr, remoteaddr;
    int clientaddrlen = sizeof(clientaddr), remoteaddrlen = sizeof(remoteaddr);
    int localport = 8080, remoteport = 0;

    int ret = parse_arguments(argc, argv, &verbose, &obfuscate, localhost, remotehost, &localport, &remoteport, &localaddr, &clientaddr, &remoteaddr);
    if (ret == EXIT_SUCCESS || ret == EXIT_FAILURE)
    {
        return ret;
    }

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
