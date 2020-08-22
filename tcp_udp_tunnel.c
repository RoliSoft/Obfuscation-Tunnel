#include "shared.c"

int main(int argc, char* argv[])
{
    int verbose = 0, obfuscate = 0, remotebound = 0, res;
    int serverfd, remotefd, clientfd;
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

            unsigned short toread = read_14bit(clientfd);

            if (toread == 0)
            {
                printf("TCP connection to client lost\n");
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
                socklen_t msglen = read(clientfd, (char*)buffer + (readsize - toread), toread);

                if (verbose && toread != msglen)
                {
                    printf("Read partially, need %u more bytes.\n", toread - msglen);
                }

                toread -= msglen;
            }

            if (verbose) printf("Received %d bytes from client\n", readsize);
            if (obfuscate) obfuscate_message(buffer, readsize);

            res = sendto(remotefd, (char*)buffer, readsize, 0, (const struct sockaddr *)&remoteaddr, remoteaddrlen);
        }

        if (fds[1].revents & POLLIN)
        {
            // udp -> tcp

            socklen_t msglen = recvfrom(remotefd, ((char*)buffer) + sizeof(unsigned short), MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&remoteaddr, (unsigned int*)&remoteaddrlen);

            if (verbose) printf("Received %d bytes from remote\n", msglen);
            if (obfuscate) obfuscate_message(((char*)buffer) + sizeof(unsigned short), msglen);

            int sizelen = 0;
            write_14bit(msglen, (char*)buffer, &sizelen);
            int sizediff = sizeof(unsigned short) - sizelen;

            if (sizediff == 1)
            {
                buffer[1] = buffer[0];
            }

            res = write(clientfd, (char*)buffer + sizediff, msglen + sizelen);
        }
    }

    close(remotefd);

    return 0;
}