#include "shared.c"

void icmp_udp_server_to_remote_loop(struct session *s)
{
    int res;
    char buffer[MTU_SIZE];
    socklen_t addrlen = IP_SIZE;
    int active_fd;
    int skip = 0, is_v6 = 0;
    struct sockaddr_in6 temp_addr;

    struct pollfd fds[2];
    memset(fds, 0 , sizeof(fds));
    fds[0].fd = s->server_fd;
    fds[0].events = POLLIN;
    fds[1].fd = s->client_fd;
    fds[1].events = POLLIN;

    while (run)
    {
        // icmp -> udp

        if (!s->connected)
        {
            if (s->verbose) printf("Waiting for first packet from client...\n");

            res = poll(fds, 2, 1000);

            if (res == 0)
            {
                continue;
            }
            else if (res < 0)
            {
                if (run)
                {
                    perror("poll failed");
                    return;
                }
                else
                {
                printf("exit\n");
                    return;
                }
            }

            if (fds[0].revents & POLLIN)
            {
                is_v6 = 1;
                skip = ICMP6_SKIP;
                active_fd = fds[0].fd;
            }
            else if (fds[1].revents & POLLIN)
            {
                is_v6 = 0;
                skip = ICMP_SKIP;
                active_fd = fds[1].fd;
            }

            socklen_t msglen = recvfrom(active_fd, (char*)buffer, MTU_SIZE, 0, (struct sockaddr*)&temp_addr, &addrlen);

            if (msglen == -1)
            {
                if (run)
                {
                    perror("failed to read ICMP packet");
                }

                continue;
            }

            if (is_v6)
            {
                if ((unsigned char)buffer[0] != 0x80 || (unsigned char)buffer[4] != 0x13 || (unsigned char)buffer[5] != 0x37)
                {
                    continue;
                }
            }
            else
            {
                if ((unsigned char)buffer[IPHDR_LEN] != 0x08 || (unsigned char)buffer[4 + IPHDR_LEN] != 0x13 || (unsigned char)buffer[5 + IPHDR_LEN] != 0x37)
                {
                    continue;
                }
            }
            
            s->client_addr = temp_addr;
            upgrade_v4mapped(&s->client_addr);
            
            printf("Client connected from ");
            print_ip(&s->client_addr);
            printf("\n");

            if (s->verbose) printf("Received %d bytes from client\n", msglen - skip);
            if (s->obfuscate) obfuscate_message(buffer + skip, msglen - skip);

            s->sequence = *((unsigned short*)&buffer[ICMP_SEQ_OFFSET + (is_v6 ? 0 : IPHDR_LEN)]);

            res = sendto(s->remote_fd, (char*)buffer + skip, msglen - skip, 0, (const struct sockaddr *)&s->remote_addr, IP_SIZE);

            if (res < 0)
            {
                perror("failed to send UDP packet");
            }

            s->connected = 1;
            continue;
        }

        res = poll(fds, 2, 1000);

        if (res == 0)
        {
            continue;
        }
        else if (res < 0)
        {
            if (run)
            {
                perror("poll failed");
                return;
            }
            else
            {
                printf("exit\n");
                return;
            }
        }

        if (fds[0].revents & POLLIN)
        {
            is_v6 = 1;
            skip = ICMP6_SKIP;
            active_fd = fds[0].fd;
        }
        else if (fds[1].revents & POLLIN)
        {
            is_v6 = 0;
            skip = ICMP_SKIP;
            active_fd = fds[1].fd;
        }

        socklen_t msglen = recvfrom(active_fd, (char*)buffer, MTU_SIZE, 0, (struct sockaddr*)&temp_addr, &addrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("failed to read ICMP packet");
            }

            continue;
        }

        if (is_v6)
        {
            if ((unsigned char)buffer[0] != 0x80 || (unsigned char)buffer[4] != 0x13 || (unsigned char)buffer[5] != 0x37)
            {
                continue;
            }
        }
        else
        {
            if ((unsigned char)buffer[IPHDR_LEN] != 0x08 || (unsigned char)buffer[4 + IPHDR_LEN] != 0x13 || (unsigned char)buffer[5 + IPHDR_LEN] != 0x37)
            {
                continue;
            }
        }
        
        s->client_addr = temp_addr;
        upgrade_v4mapped(&s->client_addr);

        if (s->verbose) printf("Received %d bytes from client\n", msglen - skip);
        if (s->obfuscate) obfuscate_message(buffer + skip, msglen - skip);

        s->sequence = ntohs(*((unsigned short*)&buffer[ICMP_SEQ_OFFSET  + (is_v6 ? 0 : IPHDR_LEN)]));

        res = sendto(s->remote_fd, (char*)buffer + skip, msglen - skip, 0, (const struct sockaddr *)&s->remote_addr, IP_SIZE);

        if (res < 0)
        {
            perror("failed to send UDP packet");
        }
    }
}

void icmp_udp_server_to_remote_pcap_loop(struct session *s)
{
    int res;
    const u_char *cap_buffer;
    struct pcap_pkthdr *cap_data;
    int skip = 0;

    while (run)
    {
        // icmp -> udp

        if (!s->connected)
        {
            if (s->verbose) printf("Waiting for first packet from client...\n");

            res = pcap_next_ex(s->cap_ptr, &cap_data, &cap_buffer);

            if (res == 0)
            {
                sleep(1);
                continue;
            }
            else if (res < 0)
            {
                if (run)
                {
                    pcap_perror(s->cap_ptr, "failed to read ICMP packet");
                }

                continue;
            }

            pcap_extract_source(cap_buffer, cap_data->caplen, &s->client_addr);
            skip = s->client_addr.sin6_family == AF_INET6 ? PCAP_ICMP6_SKIP : PCAP_ICMP_SKIP;

            printf("Client connected from ");
            print_ip(&s->client_addr);
            printf("\n");
            
            if (s->verbose) printf("Received %d bytes from client\n", cap_data->caplen - skip);
            if (s->obfuscate) obfuscate_message((char*)cap_buffer + skip, cap_data->caplen - skip);

            res = sendto(s->remote_fd, (char*)cap_buffer + skip, cap_data->caplen - skip, 0, (const struct sockaddr *)&s->remote_addr, IP_SIZE);

            if (res < 0)
            {
                perror("failed to send UDP packet");
            }

            s->connected = 1;
            continue;
        }

        res = pcap_next_ex(s->cap_ptr, &cap_data, &cap_buffer);

        if (res < 1)
        {
            if (res == -1 && run)
            {
                pcap_perror(s->cap_ptr, "failed to read ICMP packet");
            }

            continue;
        }

        pcap_extract_source(cap_buffer, cap_data->caplen, &s->client_addr);
        skip = s->client_addr.sin6_family == AF_INET6 ? PCAP_ICMP6_SKIP : PCAP_ICMP_SKIP;

        if (s->verbose) printf("Received %d bytes from client\n", cap_data->caplen - skip);
        if (s->obfuscate) obfuscate_message((char*)cap_buffer + skip, cap_data->caplen - skip);

        s->sequence = ntohs(*((unsigned short*)&cap_buffer[ETHHDR_LEN + (s->client_addr.sin6_family == AF_INET6 ? IP6HDR_LEN : IPHDR_LEN) + ICMP_SEQ_OFFSET]));

        res = sendto(s->remote_fd, (char*)cap_buffer + skip, cap_data->caplen - skip, 0, (const struct sockaddr *)&s->remote_addr, IP_SIZE);

        if (res < 0)
        {
            perror("failed to send UDP packet");
        }
    }
}

void icmp_udp_remote_to_server_loop(struct session *s)
{
    int res;
    char buffer[MTU_SIZE];
    socklen_t addrlen = IP_SIZE;

    while (run)
    {
        // udp -> icmp

        if (!s->connected)
        {
            sleep(1);
            continue;
        }

        socklen_t msglen = recvfrom(s->remote_fd, (char*)buffer + ICMP_LEN, MTU_SIZE - ICMP_LEN, MSG_WAITALL, (struct sockaddr*)&s->remote_addr, &addrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("failed to read UDP packet");
            }

            continue;
        }
        
        if (s->verbose) printf("Received %d bytes from remote\n", msglen);
        if (s->obfuscate) obfuscate_message(buffer + ICMP_LEN, msglen - ICMP_LEN);

        *((unsigned short*)&buffer) = s->client_addr.sin6_family == AF_INET6 ? 0x81 : 0x00; // type -> echo reply
        *((unsigned short*)&buffer[4]) = 0x3713; // identifier
        *((unsigned short*)&buffer[6]) = htons(s->sequence); // sequence
        *((unsigned short*)&buffer[2]) = 0; // zero checksum before calculation
        *((unsigned short*)&buffer[2]) = ip_checksum((char*)&buffer, msglen + ICMP_LEN);

        res = sendto(s->client_addr.sin6_family == AF_INET6 ? s->server_fd : s->client_fd, (char*)buffer, msglen + ICMP_LEN, 0, (const struct sockaddr *)&s->client_addr, IP_SIZE);

        if (res < 0)
        {
            perror("failed to send ICMP packet");
        }
    }
}

int icmp_udp_tunnel(struct session *s)
{
    // as raw sockets don't support IPv4 and IPv6 at the same time,
    // and it cannot be decided at runtime which one to use (like with udp_icmp),
    // we'll have to listen on two sockets, and reuse the client_fd from TCP

    if ((s->server_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    { 
        perror("server socket creation failed");
        return EXIT_FAILURE;
    }

    if ((s->client_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    { 
        perror("server socket creation failed");
        return EXIT_FAILURE;
    }

    if ((s->remote_fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
    { 
        perror("gateway socket creation failed");
        return EXIT_FAILURE;
    }

    if (s->pcap)
    {
        pcap_if_t *capdevs;
        char caperr[PCAP_ERRBUF_SIZE];

        pcap_findalldevs(&capdevs, caperr);
        if (capdevs == NULL)
        {
            printf("Error finding devices: %s\n", caperr);
            return EXIT_FAILURE;
        }

        char* capdev = capdevs->name;
        s->cap_ptr = pcap_open_live(capdev, MTU_SIZE, 1, 1, caperr);
        if (s->cap_ptr == NULL)
        {
            fprintf(stderr, "Can't open pcap device %s: %s\n", capdev, caperr);
            return EXIT_FAILURE;
        }

        printf("Device selected for packet capture: %s\n", capdev);

        char bpf_filter[] = "(icmp[icmptype] == icmp-echo and icmp[4] == 0x13 and icmp[5] = 0x37) or (icmp6[icmp6type] == icmp6-echo and icmp6[4] == 0x13 and icmp6[5] = 0x37)";
        struct bpf_program fp;

        bpf_u_int32 net;
        if (pcap_compile(s->cap_ptr, &fp, bpf_filter, 0, net) == -1)
        {
            int still_fails = 1;
            if (s->remote_addr.sin6_family == AF_INET6)
            {
                // icmp6[] was added very recently, retry with fallback expression

                char bpf_filter_v6_2[] = "(icmp[icmptype] == icmp-echo and icmp[4] == 0x13 and icmp[5] = 0x37) or (icmp6 and ip6[40] == 0x80 and ip6[44] == 0x13 and ip6[45] = 0x37)";
                if (pcap_compile(s->cap_ptr, &fp, bpf_filter_v6_2, 0, net) != -1)
                {
                    still_fails = 0;
                }
            }

            if (still_fails)
            {
                fprintf(stderr, "Can't parse filter: %s\n", pcap_geterr(s->cap_ptr));
                return EXIT_FAILURE;
            }
        }

        if (pcap_setfilter(s->cap_ptr, &fp) == -1)
        {
            fprintf(stderr, "Can't install filter: %s\n", pcap_geterr(s->cap_ptr));
            return EXIT_FAILURE;
        }
    }

    sockets[0] = s->server_fd;
    sockets[1] = s->client_fd;
    sockets[2] = s->remote_fd;

    if (s->obfuscate) printf("Header obfuscation enabled.\n");

    pthread_t threads[2];

    if (s->pcap)
    {
        pthread_create(&threads[1], NULL, (void*(*)(void*))&icmp_udp_server_to_remote_pcap_loop, (void*)s);
    }
    else
    {
        pthread_create(&threads[1], NULL, (void*(*)(void*))&icmp_udp_server_to_remote_loop, (void*)s);
    }

    pthread_create(&threads[0], NULL, (void*(*)(void*))&icmp_udp_remote_to_server_loop, (void*)s);

    for (int i = 0; i < sizeof(threads) / sizeof(threads[0]); i++)
    {
        pthread_join(threads[i], NULL);  
    }

    pthread_exit(NULL);

    close(s->server_fd);
    close(s->client_fd);
    close(s->remote_fd);

    return 0;
}
