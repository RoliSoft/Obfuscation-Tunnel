#include "shared.c"

struct udp_tcp_session
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
};

int udp_tcp_server_to_remote_loop(struct udp_tcp_session *s)
{
    int res;
    char buffer[MTU_SIZE + sizeof(unsigned short)];

    while (run)
    {
        // udp -> tcp

        socklen_t msglen = recvfrom(s->serverfd, ((char*)buffer) + sizeof(unsigned short), MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&s->clientaddr, (unsigned int*)&s->clientaddrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("failed to read UDP packet");
            }

            continue;
        }

        if (s->verbose) printf("Received %d bytes from client\n", msglen);
        if (s->obfuscate) obfuscate_message(((char*)buffer) + sizeof(unsigned short), msglen);

        int sizelen = 0;
        write_14bit(msglen, (char*)buffer, &sizelen);
        int sizediff = sizeof(unsigned short) - sizelen;

        if (sizediff == 1)
        {
            buffer[1] = buffer[0];
        }

        res = write(s->remotefd, (char*)buffer + sizediff, msglen + sizelen);
    }

    return EXIT_SUCCESS;
}

int udp_tcp_remote_to_server_loop(struct udp_tcp_session *s)
{
    int res;
    char buffer[MTU_SIZE + sizeof(unsigned short)];

    while (run)
    {
        // tcp -> udp

        unsigned short toread = read_14bit(s->remotefd);

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

        while (toread > 0 && run)
        {
            socklen_t msglen = read(s->remotefd, (char*)buffer + (readsize - toread), toread);

            if (s->verbose && toread != msglen)
            {
                printf("Read partially, need %u more bytes.\n", toread - msglen);
            }

            toread -= msglen;
        }

        if (s->verbose) printf("Received %d bytes from remote\n", readsize);
        if (s->obfuscate) obfuscate_message(buffer, readsize);

        res = sendto(s->serverfd, (char*)buffer, readsize, 0, (const struct sockaddr *)&s->clientaddr, s->clientaddrlen);
    }

    return EXIT_SUCCESS;
}

int udp_tcp_tunnel(int verbose, int obfuscate,
                   struct sockaddr_in localaddr, int localport,
                   struct sockaddr_in remoteaddr, int remoteport)
{
    struct udp_tcp_session s;
    memset(&s, 0, sizeof(s));

    s.verbose = verbose;
    s.obfuscate = obfuscate;
    s.localaddr = localaddr;
    s.localport = localport;
    s.remoteaddr = remoteaddr;
    s.remoteport = remoteport;
    s.clientaddrlen = sizeof(s.clientaddr);
    s.remoteaddrlen = sizeof(s.remoteaddr);

    if ((s.serverfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    { 
        perror("server socket creation failed");
        return EXIT_FAILURE;
    }

    if ((s.remotefd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
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

    printf("Connecting to remote server...\n");

    if (connect(s.remotefd, (const struct sockaddr *)&s.remoteaddr, s.remoteaddrlen) != 0)
    {
        perror("failed to connect to remote host");
        return EXIT_FAILURE;
    }

    int i = 1;
    setsockopt(s.serverfd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
#ifdef TCP_QUICKACK
    setsockopt(s.serverfd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
#endif

    //fcntl(s.remotefd, F_SETFL, O_NONBLOCK);

    if (s.obfuscate) printf("Header obfuscation enabled.\n");

    pthread_t threads[2];

    pthread_create(&threads[0], NULL, (void*(*)(void*))&udp_tcp_server_to_remote_loop, (void*)&s);
    pthread_create(&threads[1], NULL, (void*(*)(void*))&udp_tcp_remote_to_server_loop, (void*)&s);

    for (int i = 0; i < sizeof(threads) / sizeof(threads[0]); i++)
    {
        pthread_join(threads[i], NULL);  
    }

    pthread_exit(NULL);

    close(s.serverfd);
    close(s.remotefd);

    return 0;
}
