#include "shared.c"

struct udp_udp_session
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
    int remotebound;
};

void udp_udp_server_to_remote_loop(struct udp_udp_session *s)
{
    int res;
    char buffer[MTU_SIZE];

    while (run)
    {
        if (!s->remotebound)
        {
            if (s->verbose) printf("Waiting for first packet from client...\n");

            socklen_t msglen = recvfrom(s->serverfd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&s->clientaddr, (unsigned int*)&s->clientaddrlen);

            if (msglen == -1)
            {
                if (run)
                {
                    perror("failed to read UDP packet");
                }

                continue;
            }

            char clientaddrstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(s->clientaddr.sin_addr), clientaddrstr, INET_ADDRSTRLEN);
            printf("Client connected from %s:%d\n", clientaddrstr, ntohs(s->clientaddr.sin_port));

            if (s->verbose) printf("Received %d bytes from client\n", msglen);
            if (s->obfuscate) obfuscate_message(buffer, msglen);

            res = sendto(s->remotefd, (char*)buffer, msglen, 0, (const struct sockaddr *)&s->remoteaddr, s->remoteaddrlen);

            s->remotebound = 1;
            continue;
        }

        socklen_t msglen = recvfrom(s->serverfd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&s->clientaddr, (unsigned int*)&s->clientaddrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("failed to read UDP packet");
            }

            continue;
        }

        if (s->verbose) printf("Received %d bytes from client\n", msglen);
        if (s->obfuscate) obfuscate_message(buffer, msglen);

        res = sendto(s->remotefd, (char*)buffer, msglen, 0, (const struct sockaddr *)&s->remoteaddr, s->remoteaddrlen);
    }
}

void udp_udp_remote_to_server_loop(struct udp_udp_session *s)
{
    int res;
    char buffer[MTU_SIZE];

    while (run)
    {
        if (!s->remotebound)
        {
            sleep(1);
            continue;
        }

        socklen_t msglen = recvfrom(s->remotefd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&s->remoteaddr, (unsigned int*)&s->remoteaddrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("failed to read UDP packet");
            }

            continue;
        }

        if (s->verbose) printf("Received %d bytes from remote\n", msglen);
        if (s->obfuscate) obfuscate_message(buffer, msglen);

        res = sendto(s->serverfd, (char*)buffer, msglen, 0, (const struct sockaddr *)&s->clientaddr, s->clientaddrlen);
    }
}

int udp_udp_tunnel(int verbose, int obfuscate,
                   struct sockaddr_in localaddr, int localport,
                   struct sockaddr_in remoteaddr, int remoteport)
{
    struct udp_udp_session s;
    memset(&s, 0, sizeof(s));

    s.verbose = verbose;
    s.obfuscate = obfuscate;
    s.localaddr = localaddr;
    s.localport = localport;
    s.remoteaddr = remoteaddr;
    s.remoteport = remoteport;
    s.clientaddrlen = sizeof(s.clientaddr);
    s.remoteaddrlen = sizeof(s.remoteaddr);

    int res, remotebound = 0;
    char buffer[MTU_SIZE];

    if ((s.serverfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
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

    if (obfuscate) printf("Header obfuscation enabled.\n");

    if (verbose) printf("Spawning threads...\n");

    pthread_t threads[2];

    res = pthread_create(&threads[0], NULL, (void*(*)(void*))&udp_udp_server_to_remote_loop, (void*)&s);
    res = pthread_create(&threads[1], NULL, (void*(*)(void*))&udp_udp_remote_to_server_loop, (void*)&s);

    for (int i = 0; i < sizeof(threads) / sizeof(threads[0]); i++)
    {
        pthread_join(threads[i], NULL);  
    }

    pthread_exit(NULL);

    close(s.serverfd);
    close(s.remotefd);

    return 0;
}
