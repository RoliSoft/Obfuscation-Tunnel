#include "shared.c"

void icmp6_udp_server_to_remote_loop(struct session *s)
{
    int res;
    char buffer[MTU_SIZE];
    socklen_t addrlen = IP6_SIZE;

#ifndef AF_PACKET
    struct sockaddr_in6 temp_addr;
#endif

    while (run)
    {
        // icmp -> udp

        socklen_t msglen = recvfrom(s->server_fd, (char*)buffer, MTU_SIZE, 0, (struct sockaddr*)&
#ifdef AF_PACKET
            s->client_addr
#else
            temp_addr
#endif
            , &addrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("failed to read ICMP packet");
            }

            continue;
        }

#ifndef AF_PACKET
        if ((unsigned char)buffer[0] != 0x80 || (unsigned char)buffer[4] != 0x13 || (unsigned char)buffer[5] != 0x37)
        {
            continue;
        }

        // make sure the return address is not overwritten if not tunnel packet
        *(struct sockaddr_in6*)&s->client_addr = temp_addr;
#endif

        if (!s->connected)
        {
            s->connected = 1;

            printf("Client connected from ");
            print_ip6((struct sockaddr_in6*)&s->client_addr);
            printf("\n");
        }

        if (s->verbose) printf("Received %d bytes from client\n", msglen - ICMP6_SKIP);
        if (s->obfuscate) obfuscate_message(buffer + ICMP6_SKIP, msglen - ICMP6_SKIP);

        s->sequence = ntohs(*((unsigned short*)&buffer[ICMP_SEQ_OFFSET]));

        res = sendto(s->remote_fd, (char*)buffer + ICMP6_SKIP, msglen - ICMP6_SKIP, 0, (const struct sockaddr *)&s->remote_addr, IP_SIZE);
        
        if (res < 0)
        {
            perror("failed to send UDP packet");
        }
    }
}

#if HAVE_PCAP
void icmp6_udp_server_to_remote_pcap_loop(struct session *s)
{
    int res;
    const u_char *cap_buffer;
    struct pcap_pkthdr *cap_data;

    while (run)
    {
        // icmp -> udp

        res = pcap_next_ex(s->cap_ptr, &cap_data, &cap_buffer);

        if (res < 1)
        {
            if (run && res < 0)
            {
                pcap_perror(s->cap_ptr, "failed to read ICMP packet");
            }

            if (res == 0 && !s->connected)
            {
                sleep(1);
            }

            continue;
        }

        if (!s->connected)
        {
            s->connected = 1;

            memset(&s->client_addr, 0, sizeof(struct sockaddr_in6));
            ((struct sockaddr_in6*)&s->client_addr)->sin6_family = AF_INET6;
            ((struct sockaddr_in6*)&s->client_addr)->sin6_flowinfo = 0;
            ((struct sockaddr_in6*)&s->client_addr)->sin6_addr = *((struct in6_addr*)(cap_buffer + ETHHDR_LEN + IP6HDR_SRC_OFFSET));

            printf("Client connected from ");
            print_ip6((struct sockaddr_in6*)&s->client_addr);
            printf("\n");
        }
        else
        {
            ((struct sockaddr_in6*)&s->client_addr)->sin6_addr = *((struct in6_addr*)(cap_buffer + ETHHDR_LEN + IP6HDR_SRC_OFFSET));
        }
 
        if (s->verbose) printf("Received %d bytes from client\n", cap_data->caplen - PCAP_ICMP6_SKIP);
        if (s->obfuscate) obfuscate_message((char*)cap_buffer + PCAP_ICMP6_SKIP, cap_data->caplen - PCAP_ICMP6_SKIP);

        s->sequence = ntohs(*((unsigned short*)&cap_buffer[ETHHDR_LEN + IP6HDR_LEN + ICMP_SEQ_OFFSET]));

        res = sendto(s->remote_fd, (char*)cap_buffer + PCAP_ICMP6_SKIP, cap_data->caplen - PCAP_ICMP6_SKIP, 0, (const struct sockaddr *)&s->remote_addr, IP_SIZE);

        if (res < 0)
        {
            perror("failed to send UDP packet");
        }
    }
}
#endif

void icmp6_udp_remote_to_server_loop(struct session *s)
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
        if (s->obfuscate) obfuscate_message(buffer + ICMP_LEN, msglen);

        *((unsigned short*)&buffer) = 0x81; // type -> echo reply
        *((unsigned short*)&buffer[4]) = 0x3713; // identifier
        *((unsigned short*)&buffer[6]) = htons(s->sequence); // sequence
        *((unsigned short*)&buffer[2]) = 0; // zero checksum before calculation
        *((unsigned short*)&buffer[2]) = ip_checksum((char*)&buffer, msglen + ICMP_LEN);

        res = sendto(s->server_fd, (char*)buffer, msglen + ICMP_LEN, 0, (const struct sockaddr *)&s->client_addr, IP6_SIZE);

        if (res < 0)
        {
            perror("failed to send ICMP packet");
        }
    }
}

int icmp6_udp_tunnel(struct session *s)
{
    if ((s->server_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    { 
        perror("server socket creation failed");
        return EXIT_FAILURE;
    }

    if ((s->remote_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    { 
        perror("gateway socket creation failed");
        return EXIT_FAILURE;
    }

#if HAVE_PCAP
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

        bpf_u_int32 net;
        struct bpf_program fp;
        char bpf_filter[] = "icmp6[icmp6type] == icmp6-echo and icmp6[4] == 0x13 and icmp6[5] = 0x37";
        if (pcap_compile(s->cap_ptr, &fp, bpf_filter, 0, net) == -1)
        {
            int still_fails = 1;

            // icmp6[] was added very recently, retry with fallback expression

            char bpf_filter_legacy[] = "icmp6 and ip6[40] == 0x80 and ip6[44] == 0x13 and ip6[45] = 0x37";
            if (pcap_compile(s->cap_ptr, &fp, bpf_filter_legacy, 0, net) != -1)
            {
                still_fails = 0;
            }

            if (still_fails)
            {
                fprintf(stderr, "Can't parse filter %s: %s\n", bpf_filter, pcap_geterr(s->cap_ptr));
                return EXIT_FAILURE;
            }
        }

        if (pcap_setfilter(s->cap_ptr, &fp) == -1)
        {
            fprintf(stderr, "Can't install filter %s: %s\n", bpf_filter, pcap_geterr(s->cap_ptr));
            return EXIT_FAILURE;
        }
    }
    else
    {
#ifdef AF_PACKET
        // ip6[40] == 0x80 && ip[44] == 0x13 && ip[45] == 0x37
        // in order to offset the presence of an ethernet header assumed by pcap_compile,
        // we'll change the ip6[] to ether[]
        
        struct bpf_program bpf;
        s->cap_ptr = pcap_open_dead(DLT_EN10MB, MTU_SIZE);

        static const char bpf_filter[] = "ether[0] == 0x80 && ether[4] == 0x13 && ether[5] == 0x37";
        if (pcap_compile(s->cap_ptr, &bpf, bpf_filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
        {
            fprintf(stderr, "Can't parse filter %s: %s\n", bpf_filter, pcap_geterr(s->cap_ptr));
            return EXIT_FAILURE;
        }

        struct sock_fprog linux_bpf = {
            .len = bpf.bf_len,
            .filter = (struct sock_filter *)bpf.bf_insns,
        };

        if(setsockopt(s->server_fd, SOL_SOCKET, SO_ATTACH_FILTER, &linux_bpf, sizeof(linux_bpf)) != 0)
        {
            perror("Failed to set BPF filter on raw socket, connection may be unstable.");
        }

        pcap_close(s->cap_ptr);
#else
        // BPF program cannot be attached to a raw socket in BSD,
        // reimplementing /dev/bpf* would essentially just be reimplementing libpcap

        printf("Packet filtering for BSD not implemented, use -p if connection is unstable.\n");
#endif
    }
#else
    printf("ICMP tunnels are much faster and stable when used with PCAP.\n");
#endif

    sockets[0] = s->server_fd;
    sockets[1] = s->remote_fd;

    if (s->obfuscate) printf("Header obfuscation enabled.\n");

    pthread_t threads[2];

#if HAVE_PCAP
    if (s->pcap)
    {
        pthread_create(&threads[1], NULL, (void*(*)(void*))&icmp6_udp_server_to_remote_pcap_loop, (void*)s);
    }
    else
#endif
    {
        pthread_create(&threads[1], NULL, (void*(*)(void*))&icmp6_udp_server_to_remote_loop, (void*)s);
    }

    pthread_create(&threads[0], NULL, (void*(*)(void*))&icmp6_udp_remote_to_server_loop, (void*)s);

    for (int i = 0; i < sizeof(threads) / sizeof(threads[0]); i++)
    {
        pthread_join(threads[i], NULL);  
    }

    pthread_exit(NULL);

    close(s->server_fd);
    close(s->remote_fd);

    return 0;
}
