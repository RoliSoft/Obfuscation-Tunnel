#include "shared.c"

int udp_tcp_server_to_remote_loop(struct session *s)
{
    int res;
    char buffer[MTU_SIZE + sizeof(unsigned short)];
    socklen_t addrlen = IP_SIZE;

    while (run)
    {
        // udp -> tcp

        ssize_t msglen = recvfrom(s->server_fd, ((char*)buffer) + sizeof(unsigned short), MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&s->client_addr, &addrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("failed to read UDP packet");
            }

            continue;
        }

        if (s->verbose) printf("Received %zd bytes from client\n", msglen);
        if (s->obfuscate) obfuscate_message(((char*)buffer) + sizeof(unsigned short), msglen);

        int sizelen = 0;
        write_14bit(msglen, (char*)buffer, &sizelen);
        int sizediff = sizeof(unsigned short) - sizelen;

        if (sizediff == 1)
        {
            buffer[1] = buffer[0];
        }

        res = write(s->remote_fd, (char*)buffer + sizediff, msglen + sizelen);

        if (res < 0)
        {
            perror("failed to send TCP packet");
        }
    }

    return EXIT_SUCCESS;
}

int udp_tcp_remote_to_server_loop(struct session *s)
{
    int res;
    char buffer[MTU_SIZE + sizeof(unsigned short)];

    while (run)
    {
        // tcp -> udp

        unsigned short toread = read_14bit(s->remote_fd);

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
            ssize_t msglen = read(s->remote_fd, (char*)buffer + (readsize - toread), toread);

            if (s->verbose && toread != msglen)
            {
                printf("Read partially, need %ld more bytes.\n", toread - msglen);
            }

            toread -= msglen;
        }

        if (s->verbose) printf("Received %d bytes from remote\n", readsize);
        if (s->obfuscate) obfuscate_message(buffer, readsize);

        res = sendto(s->server_fd, (char*)buffer, readsize, 0, (const struct sockaddr *)&s->client_addr, IP_SIZE);

        if (res < 0)
        {
            perror("failed to send UDP packet");
        }
    }

    return EXIT_SUCCESS;
}

int udp_tcp_tunnel(struct session *s)
{
    if ((s->server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    { 
        perror("server socket creation failed");
        return EXIT_FAILURE;
    }

    if ((s->remote_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    { 
        perror("gateway socket creation failed");
        return EXIT_FAILURE;
    }

    sockets[0] = s->server_fd;
    sockets[1] = s->remote_fd;

    if (bind(s->server_fd, (const struct sockaddr *)&s->local_addr, sizeof(s->local_addr)) < 0)
    {
        perror("bind failed");
        return EXIT_FAILURE;
    }

    printf("Connecting to remote server...\n");

    if (connect(s->remote_fd, (const struct sockaddr *)&s->remote_addr, IP_SIZE) != 0)
    {
        perror("failed to connect to remote host");
        return EXIT_FAILURE;
    }

    int i = 1;
    setsockopt(s->server_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
#ifdef TCP_QUICKACK
    setsockopt(s->server_fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
#endif

    //fcntl(s->remote_fd, F_SETFL, O_NONBLOCK);

    if (s->obfuscate) printf("Header obfuscation enabled.\n");

    pthread_t threads[2];

    pthread_create(&threads[0], NULL, (void*(*)(void*))&udp_tcp_server_to_remote_loop, (void*)s);
    pthread_create(&threads[1], NULL, (void*(*)(void*))&udp_tcp_remote_to_server_loop, (void*)s);

    for (unsigned int i = 0; i < sizeof(threads) / sizeof(threads[0]); i++)
    {
        pthread_join(threads[i], NULL);  
    }

    pthread_exit(NULL);

    close(s->server_fd);
    close(s->remote_fd);

    return 0;
}
