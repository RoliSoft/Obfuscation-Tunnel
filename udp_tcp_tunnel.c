#include "shared.c"

int udp_tcp_tunnel(int verbose, int obfuscate,
                   struct sockaddr_in localaddr, int localport,
                   struct sockaddr_in remoteaddr, int remoteport)
{
    int res, remotebound = 0;
    int serverfd, remotefd;
    struct pollfd fds[2];
    char buffer[MTU_SIZE + sizeof(unsigned short)];
    struct sockaddr_in clientaddr;
    int clientaddrlen = sizeof(clientaddr), remoteaddrlen = sizeof(remoteaddr);

    memset(&clientaddr, 0, sizeof(clientaddr));

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

    int i = 1;
    setsockopt(serverfd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
#ifdef TCP_QUICKACK
    setsockopt(serverfd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
#endif

    //fcntl(remotefd, F_SETFL, O_NONBLOCK);

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

            socklen_t msglen = recvfrom(serverfd, ((char*)buffer) + sizeof(unsigned short), MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&clientaddr, (unsigned int*)&clientaddrlen);

            if (verbose) printf("Received %d bytes from client\n", msglen);
            if (obfuscate) obfuscate_message(((char*)buffer) + sizeof(unsigned short), msglen);

            int sizelen = 0;
            write_14bit(msglen, (char*)buffer, &sizelen);
            int sizediff = sizeof(unsigned short) - sizelen;

            if (sizediff == 1)
            {
                buffer[1] = buffer[0];
            }

            res = write(remotefd, (char*)buffer + sizediff, msglen + sizelen);
        }

        if (fds[1].revents & POLLIN)
        {
            // tcp -> udp

            unsigned short toread = read_14bit(remotefd);

            if (toread == 0)
            {
                printf("TCP connection to remote lost\n");
                return EXIT_FAILURE;
            }

            if (toread > MTU_SIZE)
            {
                printf("Incorrect size read from buffer, abandoning read.\n");
                continue;
            }

            unsigned short readsize = toread;

            while (toread > 0)
            {
                socklen_t msglen = read(remotefd, (char*)buffer + (readsize - toread), toread);

                if (verbose && toread != msglen)
                {
                    printf("Read partially, need %u more bytes.\n", toread - msglen);
                }

                toread -= msglen;
            }

            if (verbose) printf("Received %d bytes from remote\n", readsize);
            if (obfuscate) obfuscate_message(buffer, readsize);

            res = sendto(serverfd, (char*)buffer, readsize, 0, (const struct sockaddr *)&clientaddr, clientaddrlen);
        }
    }

    close(remotefd);

    return 0;
}
