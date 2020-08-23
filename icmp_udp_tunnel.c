#include "shared.c"
#include <pcap.h>

int icmp_udp_tunnel(int verbose, int obfuscate, int pcap,
                   struct sockaddr_in localaddr, int localport,
                   struct sockaddr_in remoteaddr, int remoteport)
{
    int res, remotebound = 0;
    int serverfd, remotefd;
    struct pollfd fds[2];
    char buffer[MTU_SIZE];
    struct sockaddr_in clientaddr;
    int clientaddrlen = sizeof(clientaddr), remoteaddrlen = sizeof(remoteaddr);
    unsigned short sequence = 0;

    char *capdev;
    pcap_t *capptr;
    const u_char *capbuffer;
    struct pcap_pkthdr capdata;

    memset(&clientaddr, 0, sizeof(clientaddr));

    if ((serverfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    { 
        perror("server socket creation failed");
        return EXIT_FAILURE;
    }

    if ((remotefd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    { 
        perror("gateway socket creation failed");
        return EXIT_FAILURE;
    }

    if (pcap)
    {
        pcap_if_t *capdevs;
        char caperr[PCAP_ERRBUF_SIZE];

        pcap_findalldevs(&capdevs, caperr);
        if (capdevs == NULL)
        {
            printf("Error finding devices: %s\n", caperr);
            return EXIT_FAILURE;
        }

        capdev = capdevs->name;
        capptr = pcap_open_live(capdev, MTU_SIZE, 1, 1, caperr);
        if (capptr == NULL)
        {
            fprintf(stderr, "Can't open pcap device %s: %s\n", capdev, caperr);
            return EXIT_FAILURE;
        }

        printf("Device selected for packet capture: %s\n", capdev);

        char bpf_filter[] = "icmp[icmptype] == icmp-echo and icmp[4] == 0x13 and icmp[5] = 0x37";
        struct bpf_program fp;

        bpf_u_int32 net;
        if (pcap_compile(capptr, &fp, bpf_filter, 0, net) == -1)
        {
            fprintf(stderr, "Can't parse filter %s: %s\n", bpf_filter, pcap_geterr(capptr));
            return EXIT_FAILURE;
        }

        if (pcap_setfilter(capptr, &fp) == -1)
        {
            fprintf(stderr, "Can't install filter %s: %s\n", bpf_filter, pcap_geterr(capptr));
            return EXIT_FAILURE;
        }
    }

    sockets[0] = serverfd;
    sockets[1] = remotefd;

    memset(fds, 0 , sizeof(fds));
    fds[1].fd = remotefd;
    fds[1].events = POLLIN;

    if (pcap)
    {
        fds[0].fd = pcap_get_selectable_fd(capptr);
        fds[0].events = POLLIN;
    }
    else
    {
        fds[0].fd = serverfd;
        fds[0].events = POLLIN;
    }

    if (obfuscate) printf("Header obfuscation enabled.\n");

    while (run)
    {
        if (!remotebound)
        {
            if (verbose) printf("Waiting for first packet from client...\n");

            if (pcap)
            {
                capbuffer = pcap_next(capptr, &capdata);

                if (capbuffer == NULL)
                {
                    sleep(1);
                    continue;
                }

                memset(&clientaddr, 0, sizeof(clientaddr));
                clientaddr.sin_family = AF_INET;
                clientaddr.sin_addr = *((struct in_addr*)((char*)capbuffer + ETHHDR_LEN + IPHDR_SRC_OFFSET));

                char clientaddrstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(clientaddr.sin_addr), clientaddrstr, INET_ADDRSTRLEN);
                printf("Client connected from %s\n", clientaddrstr);
                
                if (verbose) printf("Received %d bytes from client\n", capdata.caplen - PCAP_ICMP_SKIP);
                if (obfuscate) obfuscate_message(buffer + PCAP_ICMP_SKIP, capdata.caplen - PCAP_ICMP_SKIP);

                res = sendto(remotefd, (char*)capbuffer + PCAP_ICMP_SKIP, capdata.caplen - PCAP_ICMP_SKIP, 0, (const struct sockaddr *)&remoteaddr, remoteaddrlen);
            }
            else
            {
                socklen_t msglen = recvfrom(serverfd, (char*)buffer, MTU_SIZE, 0, (struct sockaddr*)&clientaddr, (unsigned int*)&clientaddrlen);

                if (msglen == -1)
                {
                    if (run)
                    {
                        perror("failed to read ICMP packet");
                    }

                    continue;
                }

                char clientaddrstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(clientaddr.sin_addr), clientaddrstr, INET_ADDRSTRLEN);
                printf("Client connected from %s\n", clientaddrstr);

                if (verbose) printf("Received %d bytes from client\n", msglen - ICMP_SKIP);
                if (obfuscate) obfuscate_message(buffer + ICMP_SKIP, msglen - ICMP_SKIP);

                sequence = *((unsigned short*)&buffer[6 + IPHDR_LEN]);

                res = sendto(remotefd, (char*)buffer + ICMP_SKIP, msglen - ICMP_SKIP, 0, (const struct sockaddr *)&remoteaddr, remoteaddrlen);
            }

            remotebound = 1;
            continue;
        }

        if (verbose) printf("Polling...\n");

        res = poll(fds, 2, (3 * 60 * 1000));
        
        if (res == 0)
        {
            continue;
        }
        else if (res < 0)
        {
            if (run)
            {
                perror("poll failed");
                return EXIT_FAILURE;
            }
            else
            {
                return EXIT_SUCCESS;
            }
        }

        if (fds[0].revents & POLLIN)
        {
            if (pcap)
            {
                capbuffer = pcap_next(capptr, &capdata);

                if (capbuffer == NULL)
                {
                    if (run)
                    {
                        perror("failed to read ICMP packet");
                    }

                    continue;
                }

                clientaddr.sin_addr = *((struct in_addr*)((char*)capbuffer + ETHHDR_LEN + IPHDR_SRC_OFFSET));

                if (verbose) printf("Received %d bytes from client\n", capdata.caplen - PCAP_ICMP_SKIP);
                if (obfuscate) obfuscate_message(buffer + PCAP_ICMP_SKIP, capdata.caplen - PCAP_ICMP_SKIP);

                sequence = ntohs(*((unsigned short*)&buffer[ETHHDR_LEN + IPHDR_LEN + ICMP_SEQ_OFFSET]));

                res = sendto(remotefd, (char*)capbuffer + PCAP_ICMP_SKIP, capdata.caplen - PCAP_ICMP_SKIP, 0, (const struct sockaddr *)&remoteaddr, remoteaddrlen);
            }
            else
            {
                socklen_t msglen = recvfrom(serverfd, (char*)buffer, MTU_SIZE, 0, (struct sockaddr*)&clientaddr, (unsigned int*)&clientaddrlen);

                if (msglen == -1)
                {
                    if (run)
                    {
                        perror("failed to read ICMP packet");
                    }

                    continue;
                }

                if (verbose) printf("Received %d bytes from client\n", msglen - ICMP_SKIP);
                if (obfuscate) obfuscate_message(buffer + ICMP_SKIP, msglen - ICMP_SKIP);

                sequence = ntohs(*((unsigned short*)&buffer[IPHDR_LEN + ICMP_SEQ_OFFSET]));

                res = sendto(remotefd, (char*)buffer + ICMP_SKIP, msglen - ICMP_SKIP, 0, (const struct sockaddr *)&remoteaddr, remoteaddrlen);
            }
        }

        if (fds[1].revents & POLLIN)
        {
            socklen_t msglen = recvfrom(remotefd, (char*)buffer + ICMP_LEN, MTU_SIZE - ICMP_LEN, MSG_WAITALL, (struct sockaddr*)&remoteaddr, (unsigned int*)&remoteaddrlen);

            if (msglen == -1)
            {
                if (run)
                {
                    perror("failed to read UDP packet");
                }

                continue;
            }

            if (verbose) printf("Received %d bytes from remote\n", msglen);
            if (obfuscate) obfuscate_message(buffer + ICMP_LEN, msglen - ICMP_LEN);

            *((unsigned short*)&buffer) = 0; // type -> echo reply
            *((unsigned short*)&buffer[4]) = 0x3713; // identifier
            *((unsigned short*)&buffer[6]) = htons(sequence); // sequence
            *((unsigned short*)&buffer[2]) = 0; // zero checksum before calculation
            *((unsigned short*)&buffer[2]) = ip_checksum((char*)&buffer, msglen + ICMP_LEN);

            res = sendto(serverfd, (char*)buffer, msglen + ICMP_LEN, 0, (const struct sockaddr *)&clientaddr, clientaddrlen);
        }
    }

    close(serverfd);
    close(remotefd);

    return 0;
}
