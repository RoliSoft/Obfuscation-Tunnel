#include "shared.c"

int tcp_udp_client_to_remote_loop(struct session *s)
{
    int res;
    char buffer[MTU_SIZE];

    while (run)
    {
        // tcp -> udp

        unsigned short toread = read_14bit(s->client_fd);

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
            socklen_t msglen = read(s->client_fd, (char*)buffer + (readsize - toread), toread);

            if (s->verbose && toread != msglen)
            {
                printf("Read partially, need %u more bytes.\n", toread - msglen);
            }

            toread -= msglen;
        }

        if (s->verbose) printf("Received %d bytes from client\n", readsize);
        if (s->obfuscate) obfuscate_message(buffer, readsize);

        res = sendto(s->remote_fd, (char*)buffer, readsize, 0, (const struct sockaddr *)&s->remote_addr, IP_SIZE);
    }

    return EXIT_SUCCESS;
}

int tcp_udp_remote_to_client_loop(struct session *s)
{
    int res;
    char buffer[MTU_SIZE];
    socklen_t addrlen;

    while (run)
    {
        // udp -> tcp

        socklen_t msglen = recvfrom(s->remote_fd, ((char*)buffer) + sizeof(unsigned short), MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&s->remote_addr, &addrlen);

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

        res = write(s->client_fd, (char*)buffer + sizediff, msglen + sizelen);
    }

    return EXIT_SUCCESS;
}

int tcp_udp_tunnel(struct session *s)
{
    if ((s->server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    { 
        perror("server socket creation failed");
        return EXIT_FAILURE;
    }

    if ((s->remote_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
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

    if (listen(s->server_fd, 1) != 0)
    {
        perror("failed to listen on local port");
        return EXIT_FAILURE;
    }

    printf("Waiting for first client...\n");

    socklen_t addrlen;
    s->client_fd = accept(s->server_fd, (struct sockaddr*)&s->client_addr, &addrlen);

    if (s->client_fd < 0)
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

    sockets[2] = s->client_fd;

    char clientaddrstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(s->client_addr.sin_addr), clientaddrstr, INET_ADDRSTRLEN);
    printf("Client connected from %s:%d\n", clientaddrstr, ntohs(s->client_addr.sin_port));

    int i = 1;
    setsockopt(s->client_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
#ifdef TCP_QUICKACK
    setsockopt(s->client_fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
#endif

    //fcntl(s->client_fd, F_SETFL, O_NONBLOCK);

    if (s->obfuscate) printf("Header obfuscation enabled.\n");

    pthread_t threads[2];

    pthread_create(&threads[0], NULL, (void*(*)(void*))&tcp_udp_client_to_remote_loop, (void*)s);
    pthread_create(&threads[1], NULL, (void*(*)(void*))&tcp_udp_remote_to_client_loop, (void*)s);

    for (int i = 0; i < sizeof(threads) / sizeof(threads[0]); i++)
    {
        pthread_join(threads[i], NULL);  
    }

    pthread_exit(NULL);

    close(s->client_fd);
    close(s->server_fd);
    close(s->remote_fd);

    return 0;
}
