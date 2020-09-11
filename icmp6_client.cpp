#pragma once
#include "shared.cpp"
#include "icmp6_base.cpp"

class icmp6_client : public icmp6_base
{
private:
    int fd;
    struct sockaddr_in6 remote_addr;

public:
    icmp6_client(struct session* session)
        : transport_base(session->verbose), icmp6_base(session->pcap, session->cap_dev, session->random_id), remote_addr(*(struct sockaddr_in6*)&session->remote_addr)
    {
    }

    icmp6_client(struct sockaddr_in6 remote_addr, bool pcap = false, char *cap_dev = NULL, bool random_id = false, bool verbose = false)
        : transport_base(verbose), icmp6_base(pcap, cap_dev, random_id), remote_addr(remote_addr)
    {
    }

    int start()
    {
        if ((this->fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
        { 
            perror("Client socket creation failed");
            return EXIT_FAILURE;
        }

#if HAVE_PCAP
        if (this->pcap)
        {
            pcap_if_t *cap_devs;
            char cap_err[PCAP_ERRBUF_SIZE];

            if (this->cap_dev == NULL)
            {
                pcap_findalldevs(&cap_devs, cap_err);
                if (cap_devs == NULL)
                {
                    printf("Error finding devices: %s\n", cap_err);
                    return EXIT_FAILURE;
                }

                this->cap_dev = cap_devs->name;
            }

            this->cap_ptr = pcap_open_live(this->cap_dev, MTU_SIZE, 1, 1, cap_err);
            if (this->cap_ptr == NULL)
            {
                fprintf(stderr, "Can't open pcap device %s: %s\n", this->cap_dev, cap_err);
                return EXIT_FAILURE;
            }

            printf("Device selected for packet capture: %s\n", this->cap_dev);

            struct bpf_program fp;
            static const char bpf_filter[] = "icmp6[icmp6type] == icmp6-echoreply and icmp6[4] == 0x13 and icmp6[5] = 0x37";
            if (pcap_compile(this->cap_ptr, &fp, bpf_filter, 0, 0) == -1)
            {
                int still_fails = 1;

                // icmp6[] was added very recently, retry with fallback expression

                char bpf_filter_legacy[] = "icmp6 and ip6[40] == 0x81 and ip6[44] == 0x13 and ip6[45] = 0x37";
                if (pcap_compile(this->cap_ptr, &fp, bpf_filter_legacy, 0, 0) != -1)
                {
                    still_fails = 0;
                }

                if (still_fails)
                {
                    fprintf(stderr, "Can't parse filter %s: %s\n", bpf_filter, pcap_geterr(this->cap_ptr));
                    return EXIT_FAILURE;
                }
            }

            if (pcap_setfilter(this->cap_ptr, &fp) == -1)
            {
                fprintf(stderr, "Can't install filter %s: %s\n", bpf_filter, pcap_geterr(this->cap_ptr));
                return EXIT_FAILURE;
            }
        }
        else
        {
            printf("You should consider adding -p for PCAP when remote is ICMPv6.\n");

#ifdef AF_PACKET
            // ip6[40] == 0x81 && ip[44] == 0x13 && ip[45] == 0x37
            // in order to offset the presence of an ethernet header assumed by pcap_compile,
            // we'll change the ip6[] to ether[]
            
            struct bpf_program bpf;
            this->cap_ptr = pcap_open_dead(DLT_EN10MB, MTU_SIZE);

            static const char bpf_filter[] = "ether[0] == 0x81 && ether[4] == 0x13 && ether[5] == 0x37";
            if (pcap_compile(this->cap_ptr, &bpf, bpf_filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
            {
                fprintf(stderr, "Can't parse filter %s: %s\n", bpf_filter, pcap_geterr(this->cap_ptr));
                return EXIT_FAILURE;
            }

            struct sock_fprog linux_bpf = {
                .len = bpf.bf_len,
                .filter = (struct sock_filter *)bpf.bf_insns,
            };

            if(setsockopt(this->fd, SOL_SOCKET, SO_ATTACH_FILTER, &linux_bpf, sizeof(linux_bpf)) != 0)
            {
                perror("Failed to set BPF filter on raw socket, connection may be unstable.");
            }

            pcap_close(this->cap_ptr);
#else
            // BPF program cannot be attached to a raw socket in BSD,
            // reimplementing /dev/bpf* would essentially just be reimplementing libpcap

            printf("Packet filtering for BSD not implemented, use -p if connection is unstable.\n");
#endif
        }
#else
        printf("ICMPv6 tunnels are much faster and stable when used with PCAP.\n");
#endif

        printf("Started ICMPv6 client for ");
        print_ip6(&this->remote_addr);
        printf("\n");

        sockets2.push_back(this->fd);
        started = true;

        return EXIT_SUCCESS;
    }

    int stop()
    {
        close(this->fd);

        started = false;

        return EXIT_SUCCESS;
    }

    int send(char *buffer, ssize_t msglen)
    {
        return _send(this->fd, false, (const struct sockaddr_in6*)&this->remote_addr, buffer, msglen);
    }

    int receive(char *buffer, int* offset)
    {
        return _receive(this->fd, false, (struct sockaddr_in6*)&this->remote_addr, buffer, offset);
    }

    int get_selectable()
    {
        return this->fd;
    }
};
