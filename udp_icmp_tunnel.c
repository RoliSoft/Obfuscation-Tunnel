#include "shared.c"

void udp_icmp_server_to_remote_loop(struct session *s)
{
    int res;
    char buffer[MTU_SIZE];
    socklen_t addrlen = IP_SIZE;

    while (run)
    {
        // udp -> icmp

        if (!s->connected)
        {
            if (s->verbose) printf("Waiting for first packet from client...\n");

            socklen_t msglen = recvfrom(s->server_fd, (char*)buffer + ICMP_LEN, MTU_SIZE - ICMP_LEN, 0, (struct sockaddr*)&s->client_addr, &addrlen);

            if (msglen == -1)
            {
                if (run)
                {
                    perror("failed to read ICMP packet");
                }

                continue;
            }

            printf("Client connected from ");
            print_ip(&s->client_addr);
            printf(":%d\n", ntohs(s->client_addr.sin_port));

            if (s->verbose) printf("Received %d bytes from client\n", msglen - ICMP_LEN);
            if (s->obfuscate) obfuscate_message(buffer + ICMP_LEN, msglen - ICMP_LEN);

            *((unsigned short*)&buffer) = 8; // type -> echo request
            *((unsigned short*)&buffer[4]) = 0x3713; // identifier
            *((unsigned short*)&buffer[6]) = htons(s->sequence++); // sequence
            *((unsigned short*)&buffer[2]) = 0; // zero checksum before calculation
            *((unsigned short*)&buffer[2]) = ip_checksum((char*)&buffer, msglen + ICMP_LEN);

            res = sendto(s->remote_fd, (char*)buffer, msglen + ICMP_LEN, 0, (const struct sockaddr *)&s->remote_addr, IP_SIZE);

            if (res < 0)
            {
                perror("failed to send ICMP packet");
            }

            s->connected = 1;
            continue;
        }

        socklen_t msglen = recvfrom(s->server_fd, (char*)buffer + ICMP_LEN, MTU_SIZE - ICMP_LEN, MSG_WAITALL, (struct sockaddr*)&s->client_addr, &addrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("failed to read UDP packet");
            }

            continue;
        }

        if (s->verbose) printf("Received %d bytes from client\n", msglen - ICMP_LEN);
        if (s->obfuscate) obfuscate_message(buffer + ICMP_LEN, msglen - ICMP_LEN);

        *((unsigned short*)&buffer) = 8; // type -> echo request
        *((unsigned short*)&buffer[4]) = 0x3713; // identifier
        *((unsigned short*)&buffer[6]) = htons(s->sequence++); // sequence
        *((unsigned short*)&buffer[2]) = 0; // zero checksum before calculation
        *((unsigned short*)&buffer[2]) = ip_checksum((char*)&buffer, msglen + ICMP_LEN);

        res = sendto(s->remote_fd, (char*)buffer, msglen + ICMP_LEN, 0, (const struct sockaddr *)&s->remote_addr, IP_SIZE);

        if (res < 0)
        {
            perror("failed to send ICMP packet");
        }
    }
}

void udp_icmp_remote_to_server_loop(struct session *s)
{
    int res;
    char buffer[MTU_SIZE];
    socklen_t addrlen = IP_SIZE;

    while (run)
    {
        // icmp -> udp

        if (!s->connected)
        {
            sleep(1);
            continue;
        }

        socklen_t msglen = recvfrom(s->remote_fd, (char*)buffer, MTU_SIZE, 0, (struct sockaddr*)&s->remote_addr, &addrlen);

        if (msglen == -1)
        {
            if (run && errno != ETIMEDOUT)
            {
                perror("failed to read ICMP packet");
            }

            continue;
        }

        if (s->verbose) printf("Received %d bytes from remote\n", msglen - ICMP_SKIP);
        if (s->obfuscate) obfuscate_message(buffer + ICMP_SKIP, msglen - ICMP_SKIP);

        res = sendto(s->server_fd, (char*)buffer + ICMP_SKIP, msglen - ICMP_SKIP, 0, (const struct sockaddr *)&s->client_addr, IP_SIZE);

        if (res < 0)
        {
            perror("failed to send UDP packet");
        }
    }
}

void udp_icmp_remote_to_server_pcap_loop(struct session *s)
{
    int res;
    const u_char *cap_buffer;
    struct pcap_pkthdr cap_data;

    while (run)
    {
        // icmp -> udp

        if (!s->connected)
        {
            sleep(1);
            continue;
        }

        cap_buffer = pcap_next(s->cap_ptr, &cap_data);

        if (cap_buffer == NULL)
        {
            if (run && errno != ETIMEDOUT)
            {
                perror("failed to read ICMP packet");
            }

            continue;
        }
        
        if (s->verbose) printf("Received %d bytes from remote\n", cap_data.caplen - PCAP_ICMP_SKIP);
        if (s->obfuscate) obfuscate_message((char*)cap_buffer + PCAP_ICMP_SKIP, cap_data.caplen - PCAP_ICMP_SKIP);

        res = sendto(s->server_fd, (char*)cap_buffer + PCAP_ICMP_SKIP, cap_data.caplen - PCAP_ICMP_SKIP, 0, (const struct sockaddr *)&s->client_addr, IP_SIZE);

        if (res < 0)
        {
            perror("failed to send UDP packet");
        }
    }
}

int udp_icmp_tunnel(struct session *s)
{
    if ((s->server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    { 
        perror("server socket creation failed");
        return EXIT_FAILURE;
    }

    if ((s->remote_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    { 
        perror("gateway socket creation failed");
        return EXIT_FAILURE;
    }

    if (s->pcap)
    {
        pcap_if_t *cap_devs;
        char cap_err[PCAP_ERRBUF_SIZE];

        pcap_findalldevs(&cap_devs, cap_err);
        if (cap_devs == NULL)
        {
            printf("Error finding devices: %s\n", cap_err);
            return EXIT_FAILURE;
        }

        char* cap_dev = cap_devs->name;
        s->cap_ptr = pcap_open_live(cap_dev, MTU_SIZE, 1, 1, cap_err);
        if (s->cap_ptr == NULL)
        {
            fprintf(stderr, "Can't open pcap device %s: %s\n", cap_dev, cap_err);
            return EXIT_FAILURE;
        }

        printf("Device selected for packet capture: %s\n", cap_dev);

        char bpf_filter[] = "icmp[icmptype] == icmp-echoreply and icmp[4] == 0x13 and icmp[5] = 0x37";
        struct bpf_program fp;

        bpf_u_int32 net;
        if (pcap_compile(s->cap_ptr, &fp, bpf_filter, 0, net) == -1)
        {
            fprintf(stderr, "Can't parse filter %s: %s\n", bpf_filter, pcap_geterr(s->cap_ptr));
            return EXIT_FAILURE;
        }

        if (pcap_setfilter(s->cap_ptr, &fp) == -1)
        {
            fprintf(stderr, "Can't install filter %s: %s\n", bpf_filter, pcap_geterr(s->cap_ptr));
            return EXIT_FAILURE;
        }
    }
    else
    {
        printf("You should consider adding -p for PCAP when remote is ICMP.\n");
    }

    sockets[0] = s->server_fd;
    sockets[1] = s->remote_fd;

    if (bind(s->server_fd, (const struct sockaddr *)&s->local_addr, sizeof(s->local_addr)) < 0)
    {
        perror("bind failed");
        return EXIT_FAILURE;
    }

    if (s->obfuscate) printf("Header obfuscation enabled.\n");

    pthread_t threads[2];

    pthread_create(&threads[0], NULL, (void*(*)(void*))&udp_icmp_server_to_remote_loop, (void*)s);

    if (s->pcap)
    {
        pthread_create(&threads[1], NULL, (void*(*)(void*))&udp_icmp_remote_to_server_pcap_loop, (void*)s);
    }
    else
    {
        pthread_create(&threads[1], NULL, (void*(*)(void*))&udp_icmp_remote_to_server_loop, (void*)s);
    }

    for (int i = 0; i < sizeof(threads) / sizeof(threads[0]); i++)
    {
        pthread_join(threads[i], NULL);  
    }

    pthread_exit(NULL);

    close(s->server_fd);
    close(s->remote_fd);

    return 0;
}
