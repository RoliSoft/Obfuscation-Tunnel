#include "shared.c"

struct tcp_udp_session
{
    int verbose;
    int obfuscate;
    struct sockaddr_in localaddr;
    int localport;
    struct sockaddr_in remoteaddr;
    int remoteport;
    struct sockaddr_in clientaddr;
    int clientaddrlen;
    int remoteaddrlen;
    int serverfd;
    int remotefd;
    int clientfd;
    int remotebound;
};

int tcp_udp_client_to_remote_loop(struct tcp_udp_session *s)
{
    int res;
    char buffer[MTU_SIZE];

    while (run)
    {
        // tcp -> udp

        unsigned short toread = read_14bit(s->clientfd);

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

        while (toread > 0 && run)
        {
            socklen_t msglen = read(s->clientfd, (char*)buffer + (readsize - toread), toread);

            if (s->verbose && toread != msglen)
            {
                printf("Read partially, need %u more bytes.\n", toread - msglen);
            }

            toread -= msglen;
        }

        if (s->verbose) printf("Received %d bytes from client\n", readsize);
        if (s->obfuscate) obfuscate_message(buffer, readsize);

        res = sendto(s->remotefd, (char*)buffer, readsize, 0, (const struct sockaddr *)&s->remoteaddr, s->remoteaddrlen);
    }

    return EXIT_SUCCESS;
}

int tcp_udp_remote_to_client_loop(struct tcp_udp_session *s)
{
    int res;
    char buffer[MTU_SIZE];

    while (run)
    {
        // udp -> tcp

        socklen_t msglen = recvfrom(s->remotefd, ((char*)buffer) + sizeof(unsigned short), MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&s->remoteaddr, (unsigned int*)&s->remoteaddrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("failed to read UDP packet");
            }

            continue;
        }

        if (s->verbose) printf("Received %d bytes from remote\n", msglen);
        if (s->obfuscate) obfuscate_message(((char*)buffer) + sizeof(unsigned short), msglen);

        int sizelen = 0;
        write_14bit(msglen, (char*)buffer, &sizelen);
        int sizediff = sizeof(unsigned short) - sizelen;

        if (sizediff == 1)
        {
            buffer[1] = buffer[0];
        }

        res = write(s->clientfd, (char*)buffer + sizediff, msglen + sizelen);
    }

    return EXIT_SUCCESS;
}

int tcp_udp_tunnel(int verbose, int obfuscate,
                   struct sockaddr_in localaddr, int localport,
                   struct sockaddr_in remoteaddr, int remoteport)
{
    struct tcp_udp_session s;
    memset(&s, 0, sizeof(s));

    s.verbose = verbose;
    s.obfuscate = obfuscate;
    s.localaddr = localaddr;
    s.localport = localport;
    s.remoteaddr = remoteaddr;
    s.remoteport = remoteport;
    s.clientaddrlen = sizeof(s.clientaddr);
    s.remoteaddrlen = sizeof(s.remoteaddr);

    if ((s.serverfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    { 
        perror("server socket creation failed");
        return EXIT_FAILURE;
    }

    if ((s.remotefd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    { 
        perror("gateway socket creation failed");
        return EXIT_FAILURE;
    }

    sockets[0] = s.serverfd;
    sockets[1] = s.remotefd;

    if (bind(s.serverfd, (const struct sockaddr *)&s.localaddr, sizeof(s.localaddr)) < 0)
    {
        perror("bind failed");
        return EXIT_FAILURE;
    }

    if (listen(s.serverfd, 1) != 0)
    {
        perror("failed to listen on local port");
        return EXIT_FAILURE;
    }

    printf("Waiting for first client...\n");

    s.clientfd = accept(s.serverfd, (struct sockaddr*)&s.clientaddr, (unsigned int*)&s.clientaddrlen);

    if (s.clientfd < 0)
    {
        if (run)
        {
            perror("failed to accept incoming connection");
            return EXIT_FAILURE;
        }
        else
        {
            return EXIT_SUCCESS;
        }
    }

    sockets[2] = s.clientfd;

    char clientaddrstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(s.clientaddr.sin_addr), clientaddrstr, INET_ADDRSTRLEN);
    printf("Client connected from %s:%d\n", clientaddrstr, ntohs(s.clientaddr.sin_port));

    int i = 1;
    setsockopt(s.clientfd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
#ifdef TCP_QUICKACK
    setsockopt(s.clientfd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
#endif

    //fcntl(s.clientfd, F_SETFL, O_NONBLOCK);

    if (obfuscate) printf("Header obfuscation enabled.\n");

    pthread_t threads[2];

    pthread_create(&threads[0], NULL, (void*(*)(void*))&tcp_udp_client_to_remote_loop, (void*)&s);
    pthread_create(&threads[1], NULL, (void*(*)(void*))&tcp_udp_remote_to_client_loop, (void*)&s);

    for (int i = 0; i < sizeof(threads) / sizeof(threads[0]); i++)
    {
        pthread_join(threads[i], NULL);  
    }

    pthread_exit(NULL);

    close(s.clientfd);
    close(s.serverfd);
    close(s.remotefd);

    return 0;
}
