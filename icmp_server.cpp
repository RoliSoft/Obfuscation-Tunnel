#pragma once
#include "shared.cpp"
#include "icmp_base.cpp"

class icmp_server : public icmp_base
{
public:
    bool pcap = false;
    char *cap_dev;

private:
    int fd;
    struct sockaddr_in local_addr, client_addr;
#if HAVE_PCAP
    pcap_t *cap_ptr;
#endif

public:
    icmp_server(struct sockaddr_in local_addr, struct session* session)
        : transport_base(session->verbose), icmp_base(session->random_id), pcap(session->pcap), cap_dev(session->cap_dev), local_addr(local_addr)
    {
    }

    icmp_server(struct sockaddr_in local_addr, bool pcap = false, char *cap_dev = NULL, bool random_id = false, bool verbose = false)
        : transport_base(verbose), icmp_base(random_id), pcap(pcap), cap_dev(cap_dev), local_addr(local_addr)
    {
    }

    int start()
    {
        if ((this->fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        { 
            perror("Server socket creation failed");
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

            pcaps.push_back(this->cap_ptr);

            printf("Device selected for packet capture: %s\n", this->cap_dev);

            struct bpf_program fp;
            char *bpf_filter;
            if (this->random_id)
            {
                bpf_filter = (char*)"icmp[icmptype] == icmp-echo";
            }
            else
            {
                bpf_filter = (char*)"icmp[icmptype] == icmp-echo and icmp[4] == 0x13 and icmp[5] = 0x37";
            }

            if (pcap_compile(this->cap_ptr, &fp, bpf_filter, 0, 0) == -1)
            {
                fprintf(stderr, "Can't parse filter %s: %s\n", bpf_filter, pcap_geterr(this->cap_ptr));
                return EXIT_FAILURE;
            }

            if (pcap_setfilter(this->cap_ptr, &fp) == -1)
            {
                fprintf(stderr, "Can't install filter %s: %s\n", bpf_filter, pcap_geterr(this->cap_ptr));
                return EXIT_FAILURE;
            }
        }
        else
        {
#ifdef AF_PACKET
            // ip[20] == 0x08 && ip[24] == 0x13 && ip[25] == 0x37
            // in order to offset the presence of an ethernet header assumed by pcap_compile,
            // we'll change the ip[] to ether[]
            
            struct bpf_program bpf;
            this->cap_ptr = pcap_open_dead(DLT_EN10MB, MTU_SIZE);

            char *bpf_filter;
            if (this->random_id)
            {
                bpf_filter = (char*)"ether[20] == 0x08";
            }
            else
            {
                bpf_filter = (char*)"ether[20] == 0x08 && ether[24] == 0x13 && ether[25] == 0x37";
            }

            if (pcap_compile(this->cap_ptr, &bpf, bpf_filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
            {
                fprintf(stderr, "Can't parse filter %s: %s\n", bpf_filter, pcap_geterr(this->cap_ptr));
                return EXIT_FAILURE;
            }

            struct sock_fprog linux_bpf = {
                .len = (u_short)bpf.bf_len,
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
        printf("ICMP tunnels are much faster and stable when used with PCAP.\n");
#endif

        printf("Started ICMP server at ");
        print_ip(&this->local_addr);
        printf("\n");

        sockets.push_back(this->fd);
        started = true;

        return EXIT_SUCCESS;
    }

    int stop()
    {
        close(this->fd);

#if HAVE_PCAP
        if (this->pcap)
        {
            pcap_close(this->cap_ptr);
        }
#endif

        started = false;

        return EXIT_SUCCESS;
    }

    int send(char *buffer, ssize_t msglen)
    {
        if (!this->connected)
        {
            return 0;
        }

        return _send(this->fd, true, (const struct sockaddr*)&this->client_addr, buffer, msglen);
    }

    int receive(char *buffer, int* offset)
    {
        int res;

#if HAVE_PCAP
        if (this->pcap)
        {
            res = _receive_pcap(this->cap_ptr, true, &this->client_addr, buffer, offset);
        }
        else
        {
#endif
            res = _receive(this->fd, true, (struct sockaddr*)&this->client_addr, buffer, offset);
#if HAVE_PCAP
        }
#endif

        if (!this->connected && res > 0)
        {
            this->connected = 1;

            printf("Client connected via ICMP from ");
            print_ip(&this->client_addr);
            printf("\n");
        }

        return res;
    }

    int get_selectable()
    {
#if HAVE_PCAP
        if (this->pcap)
        {
            return pcap_get_selectable_fd(this->cap_ptr);
        }
        else
        {
#endif
            return this->fd;
#if HAVE_PCAP
        }
#endif
    }
};
