#include "shared.c"
#include <pcap.h>

struct icmp_udp_session
{
    int verbose;
    int obfuscate;
    int pcap;
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
    unsigned short sequence;
    char *capdev;
    pcap_t *capptr;
    struct pcap_pkthdr capdata;
};

void icmp_udp_server_to_remote_loop(struct icmp_udp_session *s)
{
    int res;
    char buffer[MTU_SIZE];

    while (run)
    {
        if (!s->remotebound)
        {
            if (s->verbose) printf("Waiting for first packet from client...\n");

            socklen_t msglen = recvfrom(s->serverfd, (char*)buffer, MTU_SIZE, 0, (struct sockaddr*)&s->clientaddr, (unsigned int*)&s->clientaddrlen);

            if (msglen == -1)
            {
                if (run)
                {
                    perror("failed to read ICMP packet");
                }

                continue;
            }

            char clientaddrstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(s->clientaddr.sin_addr), clientaddrstr, INET_ADDRSTRLEN);
            printf("Client connected from %s\n", clientaddrstr);

            if (s->verbose) printf("Received %d bytes from client\n", msglen - ICMP_SKIP);
            if (s->obfuscate) obfuscate_message(buffer + ICMP_SKIP, msglen - ICMP_SKIP);

            s->sequence = *((unsigned short*)&buffer[6 + IPHDR_LEN]);

            res = sendto(s->remotefd, (char*)buffer + ICMP_SKIP, msglen - ICMP_SKIP, 0, (const struct sockaddr *)&s->remoteaddr, s->remoteaddrlen);

            s->remotebound = 1;
            continue;
        }

        socklen_t msglen = recvfrom(s->serverfd, (char*)buffer, MTU_SIZE, 0, (struct sockaddr*)&s->clientaddr, (unsigned int*)&s->clientaddrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("failed to read ICMP packet");
            }

            continue;
        }

        if (s->verbose) printf("Received %d bytes from client\n", msglen - ICMP_SKIP);
        if (s->obfuscate) obfuscate_message(buffer + ICMP_SKIP, msglen - ICMP_SKIP);

        s->sequence = ntohs(*((unsigned short*)&buffer[IPHDR_LEN + ICMP_SEQ_OFFSET]));

        res = sendto(s->remotefd, (char*)buffer + ICMP_SKIP, msglen - ICMP_SKIP, 0, (const struct sockaddr *)&s->remoteaddr, s->remoteaddrlen);
    }
}

void icmp_udp_server_to_remote_pcap_loop(struct icmp_udp_session *s)
{
    int res;
    const u_char *capbuffer;
    struct pcap_pkthdr capdata;

    while (run)
    {
        if (!s->remotebound)
        {
            if (s->verbose) printf("Waiting for first packet from client...\n");

            capbuffer = pcap_next(s->capptr, &capdata);

            if (capbuffer == NULL)
            {
                sleep(1);
                continue;
            }

            memset(&s->clientaddr, 0, sizeof(s->clientaddr));
            s->clientaddr.sin_family = AF_INET;
            s->clientaddr.sin_addr = *((struct in_addr*)((char*)capbuffer + ETHHDR_LEN + IPHDR_SRC_OFFSET));

            char clientaddrstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(s->clientaddr.sin_addr), clientaddrstr, INET_ADDRSTRLEN);
            printf("Client connected from %s\n", clientaddrstr);
            
            if (s->verbose) printf("Received %d bytes from client\n", capdata.caplen - PCAP_ICMP_SKIP);
            if (s->obfuscate) obfuscate_message((char*)capbuffer + PCAP_ICMP_SKIP, capdata.caplen - PCAP_ICMP_SKIP);

            res = sendto(s->remotefd, (char*)capbuffer + PCAP_ICMP_SKIP, capdata.caplen - PCAP_ICMP_SKIP, 0, (const struct sockaddr *)&s->remoteaddr, s->remoteaddrlen);

            s->remotebound = 1;
            continue;
        }

        capbuffer = pcap_next(s->capptr, &capdata);

        if (capbuffer == NULL)
        {
            if (run)
            {
                perror("failed to read ICMP packet");
            }

            continue;
        }

        s->clientaddr.sin_addr = *((struct in_addr*)((char*)capbuffer + ETHHDR_LEN + IPHDR_SRC_OFFSET));

        if (s->verbose) printf("Received %d bytes from client\n", capdata.caplen - PCAP_ICMP_SKIP);
        if (s->obfuscate) obfuscate_message((char*)capbuffer + PCAP_ICMP_SKIP, capdata.caplen - PCAP_ICMP_SKIP);

        s->sequence = ntohs(*((unsigned short*)&capbuffer[ETHHDR_LEN + IPHDR_LEN + ICMP_SEQ_OFFSET]));

        res = sendto(s->remotefd, (char*)capbuffer + PCAP_ICMP_SKIP, capdata.caplen - PCAP_ICMP_SKIP, 0, (const struct sockaddr *)&s->remoteaddr, s->remoteaddrlen);
    }
}

void icmp_udp_remote_to_server_loop(struct icmp_udp_session *s)
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

        socklen_t msglen = recvfrom(s->remotefd, (char*)buffer + ICMP_LEN, MTU_SIZE - ICMP_LEN, MSG_WAITALL, (struct sockaddr*)&s->remoteaddr, (unsigned int*)&s->remoteaddrlen);

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

        *((unsigned short*)&buffer) = 0; // type -> echo reply
        *((unsigned short*)&buffer[4]) = 0x3713; // identifier
        *((unsigned short*)&buffer[6]) = htons(s->sequence); // sequence
        *((unsigned short*)&buffer[2]) = 0; // zero checksum before calculation
        *((unsigned short*)&buffer[2]) = ip_checksum((char*)&buffer, msglen + ICMP_LEN);

        res = sendto(s->serverfd, (char*)buffer, msglen + ICMP_LEN, 0, (const struct sockaddr *)&s->clientaddr, s->clientaddrlen);
    }
}

int icmp_udp_tunnel(int verbose, int obfuscate, int pcap,
                   struct sockaddr_in localaddr, int localport,
                   struct sockaddr_in remoteaddr, int remoteport)
{
    struct icmp_udp_session s;
    memset(&s, 0, sizeof(s));

    s.verbose = verbose;
    s.obfuscate = obfuscate;
    s.pcap = pcap;
    s.localaddr = localaddr;
    s.localport = localport;
    s.remoteaddr = remoteaddr;
    s.remoteport = remoteport;
    s.clientaddrlen = sizeof(s.clientaddr);
    s.remoteaddrlen = sizeof(s.remoteaddr);

    if ((s.serverfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    { 
        perror("server socket creation failed");
        return EXIT_FAILURE;
    }

    if ((s.remotefd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
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

        s.capdev = capdevs->name;
        s.capptr = pcap_open_live(s.capdev, MTU_SIZE, 1, 1, caperr);
        if (s.capptr == NULL)
        {
            fprintf(stderr, "Can't open pcap device %s: %s\n", s.capdev, caperr);
            return EXIT_FAILURE;
        }

        printf("Device selected for packet capture: %s\n", s.capdev);

        char bpf_filter[] = "icmp[icmptype] == icmp-echo and icmp[4] == 0x13 and icmp[5] = 0x37";
        struct bpf_program fp;

        bpf_u_int32 net;
        if (pcap_compile(s.capptr, &fp, bpf_filter, 0, net) == -1)
        {
            fprintf(stderr, "Can't parse filter %s: %s\n", bpf_filter, pcap_geterr(s.capptr));
            return EXIT_FAILURE;
        }

        if (pcap_setfilter(s.capptr, &fp) == -1)
        {
            fprintf(stderr, "Can't install filter %s: %s\n", bpf_filter, pcap_geterr(s.capptr));
            return EXIT_FAILURE;
        }
    }

    sockets[0] = s.serverfd;
    sockets[1] = s.remotefd;

    if (obfuscate) printf("Header obfuscation enabled.\n");

    pthread_t threads[2];

    if (s.pcap)
    {
        pthread_create(&threads[1], NULL, (void*(*)(void*))&icmp_udp_server_to_remote_pcap_loop, (void*)&s);
    }
    else
    {
        pthread_create(&threads[1], NULL, (void*(*)(void*))&icmp_udp_server_to_remote_loop, (void*)&s);
    }

    pthread_create(&threads[0], NULL, (void*(*)(void*))&icmp_udp_remote_to_server_loop, (void*)&s);

    for (int i = 0; i < sizeof(threads) / sizeof(threads[0]); i++)
    {
        pthread_join(threads[i], NULL);  
    }

    pthread_exit(NULL);

    close(s.serverfd);
    close(s.remotefd);

    return 0;
}
