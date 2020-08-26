#include "shared.c"

int udp_udp_server_to_remote_loop(struct session *s)
{
    int res;
    char buffer[MTU_SIZE];
    socklen_t addrlen = IP_SIZE;

    while (run)
    {
        ssize_t msglen = recvfrom(s->server_fd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&s->client_addr, &addrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("failed to read UDP packet");
            }

            continue;
        }

        if (!s->connected)
        {
            s->connected = 1;

            printf("Client connected from ");
            print_ip(&s->client_addr);
            printf(":%d\n", ntohs(s->client_addr.sin_port));
        }

        if (s->verbose) printf("Received %zd bytes from client\n", msglen);
        if (s->obfuscate) obfuscate_message(buffer, msglen);

        res = sendto(s->remote_fd, (char*)buffer, msglen, 0, (const struct sockaddr *)&s->remote_addr, IP_SIZE);

        if (res < 0)
        {
            perror("failed to send UDP packet");
        }
    }

    return EXIT_SUCCESS;
}

int udp_udp_remote_to_server_loop(struct session *s)
{
    int res;
    char buffer[MTU_SIZE];
    socklen_t addrlen = IP_SIZE;

    while (run)
    {
        if (!s->connected)
        {
            sleep(1);
            continue;
        }

        ssize_t msglen = recvfrom(s->remote_fd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&s->remote_addr, &addrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("failed to read UDP packet");
            }

            continue;
        }

        if (s->verbose) printf("Received %zd bytes from remote\n", msglen);
        if (s->obfuscate) obfuscate_message(buffer, msglen);

        res = sendto(s->server_fd, (char*)buffer, msglen, 0, (const struct sockaddr *)&s->client_addr, IP_SIZE);

        if (res < 0)
        {
            perror("failed to send UDP packet");
        }
    }

    return EXIT_SUCCESS;
}

int udp_udp_tunnel(struct session *s)
{
    if ((s->server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
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

    if (s->obfuscate) printf("Header obfuscation enabled.\n");

    if (s->verbose) printf("Spawning threads...\n");

    pthread_t threads[2];

    pthread_create(&threads[0], NULL, (void*(*)(void*))&udp_udp_server_to_remote_loop, (void*)s);
    pthread_create(&threads[1], NULL, (void*(*)(void*))&udp_udp_remote_to_server_loop, (void*)s);

    for (unsigned int i = 0; i < sizeof(threads) / sizeof(threads[0]); i++)
    {
        pthread_join(threads[i], NULL);  
    }

    pthread_exit(NULL);

    close(s->server_fd);
    close(s->remote_fd);

    return 0;
}
