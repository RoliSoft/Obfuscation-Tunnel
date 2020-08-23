#include "shared.c"

int udp_icmp_tunnel(int verbose, int obfuscate,
                   struct sockaddr_in localaddr, int localport,
                   struct sockaddr_in remoteaddr, int remoteport)
{
    int res, remotebound = 0;
    int serverfd, remotefd;
    struct pollfd fds[2];
    char buffer[MTU_SIZE];
    struct sockaddr_in clientaddr;
    int clientaddrlen = sizeof(clientaddr), remoteaddrlen = sizeof(remoteaddr);
    unsigned short sequence = 0;
    
    memset(&clientaddr, 0, sizeof(clientaddr));

    if ((serverfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    { 
        perror("server socket creation failed");
        return EXIT_FAILURE;
    }

    if ((remotefd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    { 
        perror("gateway socket creation failed");
        return EXIT_FAILURE;
    }

    sockets[0] = serverfd;
    sockets[1] = remotefd;

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

    while (run)
    {
        if (!remotebound)
        {
            if (verbose) printf("Waiting for first packet from client...\n");

            socklen_t msglen = recvfrom(serverfd, (char*)buffer + ICMP_LEN, MTU_SIZE - ICMP_LEN, 0, (struct sockaddr*)&clientaddr, (unsigned int*)&clientaddrlen);

            if (msglen == -1)
            {
                if (run)
                {
                    perror("failed to read ICMP packet");
                }

                continue;
            }

            char clientaddrstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(clientaddr.sin_addr), clientaddrstr, INET_ADDRSTRLEN);
            printf("Client connected from %s:%d\n", clientaddrstr, ntohs(clientaddr.sin_port));

            if (verbose) printf("Received %d bytes from client\n", msglen);
            if (obfuscate) obfuscate_message(buffer + ICMP_LEN, msglen - ICMP_LEN);

            *((unsigned short*)&buffer) = 8; // type -> echo request
            *((unsigned short*)&buffer[4]) = 0x3713; // identifier
            *((unsigned short*)&buffer[6]) = htons(sequence++); // sequence
            *((unsigned short*)&buffer[2]) = 0; // zero checksum before calculation
            *((unsigned short*)&buffer[2]) = ip_checksum((char*)&buffer, msglen + ICMP_LEN);

            res = sendto(remotefd, (char*)buffer, msglen + ICMP_LEN, 0, (const struct sockaddr *)&remoteaddr, remoteaddrlen);

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
            if (run)
            {
                perror("poll failed");
                return EXIT_FAILURE;
            }
            else
            {
                return EXIT_SUCCESS;
            }
        }

        if (fds[0].revents & POLLIN)
        {
            socklen_t msglen = recvfrom(serverfd, (char*)buffer + ICMP_LEN, MTU_SIZE - ICMP_LEN, MSG_WAITALL, (struct sockaddr*)&clientaddr, (unsigned int*)&clientaddrlen);

            if (msglen == -1)
            {
                if (run)
                {
                    perror("failed to read UDP packet");
                }

                continue;
            }

            if (verbose) printf("Received %d bytes from client\n", msglen);
            if (obfuscate) obfuscate_message(buffer + ICMP_LEN, msglen - ICMP_LEN);

            *((unsigned short*)&buffer) = 8; // type -> echo request
            *((unsigned short*)&buffer[4]) = 0x3713; // identifier
            *((unsigned short*)&buffer[6]) = htons(sequence++); // sequence
            *((unsigned short*)&buffer[2]) = 0; // zero checksum before calculation
            *((unsigned short*)&buffer[2]) = ip_checksum((char*)&buffer, msglen + ICMP_LEN);

            res = sendto(remotefd, (char*)buffer, msglen + ICMP_LEN, 0, (const struct sockaddr *)&remoteaddr, remoteaddrlen);
        }

        if (fds[1].revents & POLLIN)
        {
            socklen_t msglen = recvfrom(remotefd, (char*)buffer, MTU_SIZE, 0, (struct sockaddr*)&remoteaddr, (unsigned int*)&remoteaddrlen);

            if (msglen == -1)
            {
                if (run)
                {
                    perror("failed to read ICMP packet");
                }

                continue;
            }

            if (verbose) printf("Received %d bytes from remote\n", msglen - ICMP_SKIP);
            if (obfuscate) obfuscate_message(buffer + ICMP_SKIP, msglen - ICMP_SKIP);

            res = sendto(serverfd, (char*)buffer + ICMP_SKIP, msglen - ICMP_SKIP, 0, (const struct sockaddr *)&clientaddr, clientaddrlen);
        }
    }

    close(serverfd);
    close(remotefd);

    return 0;
}
